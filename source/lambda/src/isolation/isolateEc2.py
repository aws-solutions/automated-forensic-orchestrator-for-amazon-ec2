#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import datetime
import json
import os
import time
from typing import Any, Dict

import botocore
from arnparse import arnparse
from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError
from eks_token import get_token
from kubernetes import client, config

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.exception import (
    ForensicLambdaExecutionException,
    MemoryAcquisitionError,
)
from ..common.log import get_logger
from ..common.redact import redact
from ..data.datatypes import ForensicsProcessingPhase, ResourceType
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)
cluster_cache: Dict[str, Any] = {}


@xray_recorder.capture("Isolate Instance")
def handler(event, context):
    logger.info("Got event %s", redact(event))
    input_body = {}
    error_handling_flow = False
    app_account_role = os.environ["APP_ACCOUNT_ROLE"]
    logger.info("input body %s", redact(input_body))
    if event.get("Error") == MemoryAcquisitionError.__name__:
        cause = json.loads(event["Cause"])
        error_message = cause["errorMessage"]
        input_body = json.loads(error_message)
        error_handling_flow = True
    else:
        input_body = event["Payload"]["body"]
    output = input_body.copy()
    ddb_client = create_aws_client("dynamodb")
    fds = ForensicDataService(
        ddb_client=ddb_client,
        ddb_table_name=os.environ["INSTANCE_TABLE_NAME"],
        auto_notify_subscribers=(
            True
            if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
            else False
        ),
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )
    forensic_id = input_body.get("forensicId")
    forensic_record = fds.get_forensic_record(
        record_id=forensic_id, metadata_only=True
    )
    if "clusterInfo" in input_body:
        resource_type = input_body["clusterInfo"]["affectedResourceType"]
        current_account = context.invoked_function_arn.split(":")[4]
        cluster_account = input_body["instanceAccount"]
        cluster_region = input_body["instanceRegion"]
        app_account_role_arn = f"arn:aws:iam::{cluster_account}:role/ForensicEc2AllowAccessRole-us-east-1"
        eks_client = create_aws_client(
            "eks",
            current_account=current_account,
            target_account=cluster_account,
            target_region=cluster_region,
            app_account_role=app_account_role,
        )
        iam_client = create_aws_client(
            "iam",
            current_account=current_account,
            target_account=cluster_account,
            target_region=cluster_region,
            app_account_role=app_account_role,
        )
        ec2_client = create_aws_client(
            "ec2",
            current_account=current_account,
            target_account=cluster_account,
            target_region=cluster_region,
            app_account_role=app_account_role,
        )
        # Containment of Pods , Nodes attached to that
        if resource_type == "Pods" or "Deployment" or "ServiceAccount":
            try:
                # Label the pod to be Qurantined
                eks_label_pod(input_body, eks_client, app_account_role_arn)
                # Qurantine Pod with network deny policy and IAM role revocation
                eks_pod_containtment(
                    input_body, eks_client, app_account_role_arn, iam_client
                )
                # Cordon the node
                eks_cordon_node(input_body, eks_client, app_account_role_arn)
                fds.add_forensic_timeline_event(
                    id=forensic_id,
                    name=f"{resource_type} isolated",
                    description=f"{resource_type} isolated for AWSEksCluster",
                    phase=ForensicsProcessingPhase.ISOLATION,
                    component_id="isolateEksCluster",
                    component_type="Lambda",
                    event_data=None,
                )
            except Exception as e:
                logger.error(f"isolation failed, {e}")
                exception_type = e.__class__.__name__
                exception_message = str(e)
                exception_obj = {
                    "isError": True,
                    "type": exception_type,
                    "message": exception_message,
                }

                fds.add_forensic_timeline_event(
                    id=forensic_id,
                    name=f"{resource_type} isolation failed",
                    description="Node isolation for AwsEKSCluster",
                    phase=ForensicsProcessingPhase.ISOLATION_FAILED,
                    component_id="isolateEksCluster",
                    component_type="Lambda",
                    event_data=exception_obj,
                )
        elif resource_type == "Node":
            try:
                # Cordon the node
                eks_cordon_node(input_body, eks_client, app_account_role_arn)
                # Revoke session credentials from IAM Role
                invalid_existing_credential_sessions(
                    iam_client, forensic_record
                )
                instance_id = input_body.get("instanceInfo")[0].get(
                    "InstanceId"
                )
                recorded_sgs = input_body.get("instanceInfo")[0].get(
                    "SecurityGroups"
                )
                recorded_enis = input_body.get("instanceInfo")[0].get(
                    "NetworkInterfaces"
                )
                sg_for_eni = [
                    {
                        "SecurityGroup": [
                            sg.get("GroupId") for sg in item.get("Groups")
                        ],
                        "ENI_ID": item.get("NetworkInterfaceId"),
                    }
                    for item in recorded_enis
                ]
                original_sg_ids = [
                    item.get("GroupId") for item in recorded_sgs
                ]
                forensic_isolation_instance_profile_name = os.environ[
                    "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME"
                ]
                instance_vpc = input_body.get("instanceInfo")[0].get("VpcId")
                enable_evidence_protection(instance_id, ec2_client)

                enable_evidence_protection_ebs(
                    instance_id,
                    forensic_record.resourceInfo["BlockDeviceMappings"],
                    ec2_client,
                )

                (
                    isolation_sg,
                    isolation_sg_no_rule,
                ) = get_required_isolation_security_groups(
                    ec2_client, instance_vpc
                )

                logger.info(
                    f"isolating instance {instance_id}, step1 converting all traffic to untracked"
                )
                for eni in sg_for_eni:
                    eni_id = eni.get("ENI_ID")
                    ec2_client.modify_network_interface_attribute(
                        NetworkInterfaceId=eni_id, Groups=[isolation_sg]
                    )
                    ec2_client.modify_network_interface_attribute(
                        NetworkInterfaceId=eni_id,
                        Groups=[isolation_sg_no_rule],
                    )

                detach_eip_from_instance(instance_id, ec2_client)

                update_profile_for_instance(
                    instance_id,
                    cluster_account,
                    forensic_isolation_instance_profile_name,
                    ec2_client,
                    current_account,
                )
                fds.add_forensic_timeline_event(
                    id=forensic_id,
                    name=f"{resource_type} isolated",
                    description=f"{resource_type} isolated for AWSEksCluster",
                    phase=ForensicsProcessingPhase.ISOLATION,
                    component_id="isolateEksCluster",
                    component_type="Lambda",
                    event_data=None,
                )
            except Exception as e:
                logger.error(f"isolation failed, {e}")
                # best effort to revert back to original sgs
                try:
                    ec2_client.modify_instance_attribute(
                        InstanceId=instance_id, Groups=original_sg_ids
                    )
                except ForensicLambdaExecutionException:
                    logger.error("isolation reverting failed, abort")
                # revert to original sg groups
                exception_type = e.__class__.__name__
                exception_message = str(e)
                exception_obj = {
                    "isError": True,
                    "type": exception_type,
                    "message": exception_message,
                }

                fds.add_forensic_timeline_event(
                    id=forensic_id,
                    name=f"{resource_type} isolation failed",
                    description="Node isolation for AwsEKSCluster",
                    phase=ForensicsProcessingPhase.ISOLATION_FAILED,
                    component_id="isolateEksCluster",
                    component_type="Lambda",
                    event_data=exception_obj,
                )
    else:
        app_account_region = input_body.get("instanceRegion")
        instance_id = input_body.get("instanceInfo").get("InstanceId")
        recorded_sgs = input_body.get("instanceInfo").get("SecurityGroups")
        recorded_enis = input_body.get("instanceInfo").get("NetworkInterfaces")
        sg_for_eni = [
            {
                "SecurityGroup": [
                    sg.get("GroupId") for sg in item.get("Groups")
                ],
                "ENI_ID": item.get("NetworkInterfaceId"),
            }
            for item in recorded_enis
        ]
        original_sg_ids = [item.get("GroupId") for item in recorded_sgs]
        # implementation

        app_account_id = input_body.get("instanceAccount")
        current_account = context.invoked_function_arn.split(":")[4]

        forensic_isolation_instance_profile_name = os.environ[
            "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME"
        ]

        ec2_client = create_aws_client(
            "ec2",
            current_account=current_account,
            target_account=app_account_id,
            target_region=app_account_region,
            app_account_role=app_account_role,
        )

        iam_client = create_aws_client(
            "iam",
            current_account=current_account,
            target_account=app_account_id,
            target_region=app_account_region,
            app_account_role=app_account_role,
        )
        instance_vpc = input_body.get("instanceInfo").get("VpcId")
        # output = input_body.copy()

        if (
            forensic_record.memoryAnalysisStatus
            == ForensicsProcessingPhase.ISOLATION_FAILED
        ):
            logger.warning(
                f"Previous isolation fail for forensic record {forensic_id}, proceed to error handling"
            )
            raise ForensicLambdaExecutionException("Previous isolation failed")

        enable_evidence_protection(instance_id, ec2_client)

        enable_evidence_protection_ebs(
            instance_id,
            forensic_record.resourceInfo["BlockDeviceMappings"],
            ec2_client,
        )

        try:
            (
                isolation_sg,
                isolation_sg_no_rule,
            ) = get_required_isolation_security_groups(
                ec2_client, instance_vpc
            )

            logger.info(
                f"isolating instance {instance_id}, step1 converting all traffic to untracked"
            )
            for eni in sg_for_eni:
                eni_id = eni.get("ENI_ID")
                ec2_client.modify_network_interface_attribute(
                    NetworkInterfaceId=eni_id, Groups=[isolation_sg]
                )
                ec2_client.modify_network_interface_attribute(
                    NetworkInterfaceId=eni_id, Groups=[isolation_sg_no_rule]
                )

            detach_eip_from_instance(instance_id, ec2_client)

            invalid_existing_credential_sessions(iam_client, forensic_record)

            update_profile_for_instance(
                instance_id,
                app_account_id,
                forensic_isolation_instance_profile_name,
                ec2_client,
                current_account,
            )

            fds.add_forensic_timeline_event(
                id=forensic_id,
                name="Instance isolated",
                description=f"Instance isolated for {instance_id}",
                phase=ForensicsProcessingPhase.ISOLATION,
                component_id="isolateEc2",
                component_type="Lambda",
                event_data=None,
            )

        except Exception as e:
            logger.error(f"isolation failed, {e}")
            # best effort to revert back to original sgs
            try:
                ec2_client.modify_instance_attribute(
                    InstanceId=instance_id, Groups=original_sg_ids
                )
            except ForensicLambdaExecutionException:
                logger.error("isolation reverting failed, abort")
            # revert to original sg groups
            exception_type = e.__class__.__name__
            exception_message = str(e)
            exception_obj = {
                "isError": True,
                "type": exception_type,
                "message": exception_message,
            }

            fds.add_forensic_timeline_event(
                id=forensic_id,
                name="Instance isolation failed",
                description=f"Instance isolated for {instance_id} failed",
                phase=ForensicsProcessingPhase.ISOLATION_FAILED,
                component_id="isolateEc2",
                component_type="Lambda",
                event_data=exception_obj,
            )

            logger.info(
                f"Update forensic record isolation status for {forensic_record.id}"
            )
            fds.update_forensic_record_phase_status(
                id=forensic_record.id,
                memory=(
                    ForensicsProcessingPhase.ISOLATION_FAILED,
                    f"Error while isolating instance {instance_id}",
                ),
            )
            raise e
        if error_handling_flow:
            raise ForensicLambdaExecutionException(error_message)
    return create_response(200, output)


def get_cluster_info(cluster_name, eks_client):
    try:
        logger.info("Retrieve cluster endpoint and certificate")
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        endpoint = cluster_info["cluster"]["endpoint"]
        cert_authority = cluster_info["cluster"]["certificateAuthority"][
            "data"
        ]
        cluster_arn = cluster_info["cluster"]["arn"]
        cluster_info = {
            "endpoint": endpoint,
            "ca": cert_authority,
            "name": cluster_arn,
        }
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error retrieving cluster info: {e}")
        raise e
    return cluster_info


def get_bearer_token(cluster_name, cluster_admin_role_arn):
    eks_token = get_token(
        cluster_name=cluster_name, role_arn=cluster_admin_role_arn
    )
    return eks_token


def get_eks_credentials(cluster_name, eks_client, cluster_admin_role_arn):
    if cluster_name in cluster_cache:
        cluster = cluster_cache[cluster_name]
    else:
        # not present in cache retrieve cluster info from EKS service
        cluster = get_cluster_info(cluster_name, eks_client)
        # store in cache for execution environment resuse
        cluster_cache[cluster_name] = cluster
    # Get kubeconfig token
    eks_token = get_bearer_token(cluster_name, cluster_admin_role_arn)
    kubeconfig = {
        "apiVersion": "v1",
        "clusters": [
            {
                "name": cluster["name"],
                "cluster": {
                    "certificate-authority-data": cluster["ca"],
                    "server": cluster["endpoint"],
                },
            }
        ],
        "contexts": [
            {
                "name": "lambda-kubectl-context",
                "context": {
                    "cluster": cluster["name"],
                    "user": cluster["name"],
                },
            }
        ],
        "current-context": "lambda-kubectl-context",
        "kind": "Config",
        "preferences": {},
        "users": [
            {
                "name": cluster["name"],
                "user": {"token": eks_token["status"]["token"]},
            }
        ],
    }
    return kubeconfig


def create_network_policy(api_instance, namespace, policy_name, policy_spec):
    # Get the namespace network policy for label with key affected and value yes
    api_network_policy_list = api_instance.list_namespaced_network_policy(
        namespace
    )
    if len(api_network_policy_list.items) == 0:
        logger.info(
            "No Network policy exist in the namespace. Hence creating one."
        )
        body = client.V1NetworkPolicy(
            api_version="networking.k8s.io/v1",
            kind="NetworkPolicy",
            metadata=client.V1ObjectMeta(name=policy_name),
            spec=policy_spec,
        )
        try:
            api_response = api_instance.create_namespaced_network_policy(
                namespace, body
            )
            logger.info(
                "NetworkPolicy created. status='%s'" % str(api_response)
            )
        except Exception as e:
            logger.error("Error creating NetworkPolicy: %s" % e)
    else:
        for each_policy in api_network_policy_list.items:
            if each_policy.metadata.name == policy_name:
                logger.info(
                    "Network policy already exist. Hence not updating it."
                )
                pass
            else:
                try:
                    api_response = (
                        api_instance.create_namespaced_network_policy(
                            namespace, body
                        )
                    )
                    logger.info(
                        "NetworkPolicy created. status='%s'"
                        % str(api_response)
                    )
                except Exception as e:
                    logger.error("Error creating NetworkPolicy: %s" % e)


def create_sts_deny_policy_sa(
    api_instance, namespace, affected_pod_list, iam_client
):
    for affected_pod in affected_pod_list:
        pod_details = api_instance.read_namespaced_pod(
            namespace=namespace, name=affected_pod
        )
        service_account_name = pod_details.spec.service_account
        service_account_details = api_instance.read_namespaced_service_account(
            name=service_account_name, namespace=namespace
        )
        service_account_annotations = (
            service_account_details.metadata.annotations
        )
        if (
            service_account_annotations is None
            or "eks.amazonaws.com/role-arn"
            not in service_account_details.metadata.annotations
        ):
            logger.info("No IRSA exist for the Service account")
        else:
            logger.info(
                "Revoking older session for the Service account IAM Role"
            )
            current_time = datetime.datetime.now()
            service_account_iam_role_arn = service_account_annotations[
                "eks.amazonaws.com/role-arn"
            ]
            service_account_iam_role = service_account_iam_role_arn.split("/")[
                -1
            ]
            iam_client.put_role_policy(
                RoleName=service_account_iam_role,
                PolicyName="AWSRevokeOlderSTSSessions",
                PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],"Condition":{"DateLessThan":{"aws:TokenIssueTime":"'
                + current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                + '"}}}]}',
            )


def eks_pod_containtment(
    input_body, eks_client, cluster_admin_role_arn, iam_client
):
    affected_cluster = input_body["clusterInfo"]["clusterName"]
    affected_pod_list = input_body["clusterInfo"]["affectedPodResource"]
    affected_pod_namespace = input_body["clusterInfo"][
        "affectedResourceNamespace"
    ]
    get_kubeconfig = get_eks_credentials(
        affected_cluster, eks_client, cluster_admin_role_arn
    )
    config.load_kube_config_from_dict(config_dict=get_kubeconfig)
    core_api = client.CoreV1Api()
    network_api = client.NetworkingV1Api()
    policy_name = "deny-all-traffic"
    policy_spec = {
        "podSelector": {"matchLabels": {"PHASE": "QUARANTINE"}},
        "policyTypes": ["Ingress", "Egress"],
    }
    # Call the create_namespaced_network_policy function to create the network policy

    logger.info(
        f"Creating Network Policy for namespace: {affected_pod_namespace} with name: {policy_name}"
    )
    create_network_policy(
        network_api, affected_pod_namespace, policy_name, policy_spec
    )

    # Deny Permissions for the Role tied to Service account

    logger.info("Denying permissions for the role")
    create_sts_deny_policy_sa(
        core_api, affected_pod_namespace, affected_pod_list, iam_client
    )


def eks_label_pod(input_body, eks_client, cluster_admin_role_arn):
    body_label = {"metadata": {"labels": {"PHASE": "QUARANTINE"}}}
    affected_cluster = input_body["clusterInfo"]["clusterName"]
    affected_pod_list = input_body["clusterInfo"]["affectedPodResource"]
    affected_pod_namespace = input_body["clusterInfo"][
        "affectedResourceNamespace"
    ]
    get_kubeconfig = get_eks_credentials(
        affected_cluster, eks_client, cluster_admin_role_arn
    )
    config.load_kube_config_from_dict(config_dict=get_kubeconfig)
    api_instance = client.CoreV1Api()
    for affected_pod in affected_pod_list:
        logger.info(
            f"Patching the Pod {affected_pod} in namespace {affected_pod_namespace}"
        )
        api_instance.patch_namespaced_pod(
            name=affected_pod,
            namespace=affected_pod_namespace,
            body=body_label,
        )
        time.sleep(10)


def eks_cordon_node(input_body, eks_client, cluster_admin_role_arn):
    affected_cluster = input_body["clusterInfo"]["clusterName"]
    affected_pod_list = input_body["clusterInfo"]["affectedPodResource"]
    namespace = input_body["clusterInfo"]["affectedResourceNamespace"]
    affected_node = input_body["clusterInfo"]["affectedNode"]
    get_kubeconfig = get_eks_credentials(
        affected_cluster, eks_client, cluster_admin_role_arn
    )
    config.load_kube_config_from_dict(config_dict=get_kubeconfig)
    api_instance = client.CoreV1Api()
    for affected_pod in affected_pod_list:
        pod_info = api_instance.read_namespaced_pod(
            name=affected_pod, namespace=namespace
        )
        node_name = pod_info.spec.node_name
        node_info = api_instance.read_node(name=node_name)
        provider_id = node_info.spec.provider_id
        instance_id = provider_id.split("/")[-1]
        for each_affected_instance in affected_node:
            if instance_id == each_affected_instance:
                if node_info.spec.unschedulable:
                    logger.info(
                        f"Node {node_name} is already cordoned. Skipping."
                    )
                    continue
                else:
                    logger.info(f"Cordoning the node {node_name}")
                    body = {"spec": {"unschedulable": True}}
                    api_instance.patch_node(node_name, body)
                    time.sleep(10)


def invalid_existing_credential_sessions(iam_client, forensic_record):
    resource_type = forensic_record.resourceType
    logger.info(f"Process resource type: {resource_type}")
    if resource_type == ResourceType.INSTANCE:
        instance_profile = forensic_record.resourceInfo["IamInstanceProfile"]
        instance_profile_arn = forensic_record.resourceInfo[
            "IamInstanceProfile"
        ]["Arn"]
    else:
        instance_profile = forensic_record.resourceInfo[0][
            "IamInstanceProfile"
        ]
        instance_profile_arn = forensic_record.resourceInfo[0][
            "IamInstanceProfile"
        ]["Arn"]
    if not instance_profile:
        return
    parsed_arn = arnparse(instance_profile_arn)
    profile_name = parsed_arn.resource
    iam_profile_rsp = iam_client.get_instance_profile(
        InstanceProfileName=profile_name
    )

    profile_info = iam_profile_rsp.get("InstanceProfile")
    logger.info(f"Process profile: {profile_info}")
    all_role_names = [item.get("RoleName") for item in profile_info["Roles"]]
    logger.info(f"Revoke sts sessions for roles: {all_role_names}")
    current_time = datetime.datetime.now()
    for name in all_role_names:
        logger.info(
            f"Revoke access for sessions associated with role : {name}"
        )
        iam_client.put_role_policy(
            RoleName=name,
            PolicyName="AWSRevokeOlderSTSSessions",
            PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],"Condition":{"DateLessThan":{"aws:TokenIssueTime":"'
            + current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            + '"}}}]}',
        )


def detach_eip_from_instance(instance_id: str, ec2_client) -> None:
    """
    Detach any EIP associations from the target instance
    """
    logger.info(f"detach eip from instance {instance_id}")
    response = ec2_client.describe_addresses(
        Filters=[
            {
                "Name": "instance-id",
                "Values": [
                    instance_id,
                ],
            },
        ]
    )

    association_ids = [
        item.get("AssociationId") for item in response.get("Addresses")
    ]
    logger.info(f"detach eip association {association_ids}")
    for association_id in association_ids:
        ec2_client.disassociate_address(
            AssociationId=association_id,
        )


def get_required_isolation_security_groups(ec2_client, instance_vpc):
    sg_name_untrack_conversion = (
        f"Forensic-isolation-convertion-{instance_vpc}"
    )
    sg_name_no_rule = f"Forensic-isolation-no-rule-{instance_vpc}"

    check_sg_response = get_existing_security_group(
        ec2_client, [sg_name_untrack_conversion, sg_name_no_rule]
    )

    existing_sg_for_vpc = check_sg_response.get("SecurityGroups")
    logger.info(f"got existing sg {existing_sg_for_vpc}")
    existing_sg_names_for_vpc = [
        sg.get("GroupName") for sg in existing_sg_for_vpc
    ]
    logger.info(f"existing sg names {existing_sg_names_for_vpc}")

    # Group 1 to conver all traffic to untrack
    if sg_name_untrack_conversion not in existing_sg_names_for_vpc:
        logger.info(f"create security group , {sg_name_untrack_conversion}")
        response = ec2_client.create_security_group(
            Description="Forensic isolation security group untrack converting",
            GroupName=sg_name_untrack_conversion,
            VpcId=instance_vpc,
        )
        isolation_sg = response.get("GroupId")
        logger.info(f"created , {sg_name_untrack_conversion}")
        ec2_client.authorize_security_group_ingress(
            GroupId=isolation_sg,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )
    else:
        logger.info(
            f"found existing security group {sg_name_untrack_conversion} for vpc {instance_vpc}"
        )
        isolation_sg = next(
            sg.get("GroupId")
            for sg in check_sg_response.get("SecurityGroups")
            if sg.get("GroupName") == sg_name_untrack_conversion
        )

    logger.info("check for no rule sg")

    existing_sg_names_for_vpc = [
        sg.get("GroupName") for sg in existing_sg_for_vpc
    ]
    logger.info(f"creating no rule group {sg_name_no_rule}")
    # Group 2 to isolate instance
    if sg_name_no_rule not in existing_sg_names_for_vpc:
        response = ec2_client.create_security_group(
            Description="Forensic isolation security group no rule",
            GroupName=sg_name_no_rule,
            VpcId=instance_vpc,
        )
        isolation_sg_no_rule = response.get("GroupId")
        ec2_client.revoke_security_group_egress(
            GroupId=isolation_sg_no_rule,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        )
    else:
        logger.info(
            f"found existing security group {sg_name_no_rule} for vpc {instance_vpc}"
        )
        isolation_sg_no_rule = next(
            sg.get("GroupId")
            for sg in check_sg_response.get("SecurityGroups")
            if sg.get("GroupName") == sg_name_no_rule
        )

    return isolation_sg, isolation_sg_no_rule


def get_existing_security_group(ec2_client, groups_name: list):
    try:
        check_sg_response = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": groups_name},
            ]
        )
    except ClientError as e:
        # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
        # InvalidGroup.NotFound
        code = e.response["Error"]["Code"]
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            logger.error(f"both groups not exist, {code}")
            check_sg_response = {"SecurityGroups": []}
        else:
            raise e
    return check_sg_response


def enable_evidence_protection(instance_id: str, ec2_client):
    """
    perform evidence protection operation for the instance to be isolated
    """
    try:
        logger.info(f"Enable termination protection for {instance_id}")
        update_termination_protection_rsp = (
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id, DisableApiTermination={"Value": True}
            )
        )
        logger.info(
            f"Enable termination protection response {update_termination_protection_rsp}"
        )

        update_shutdown_behavior_rsp = ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            InstanceInitiatedShutdownBehavior={"Value": "stop"},
        )
        logger.info(
            f"Set shutdown behavior response {update_shutdown_behavior_rsp}"
        )
    except ClientError as e:
        logger.error(
            "instance protection operation failed, proceed to isolate"
        )
        logger.error(e)


def enable_evidence_protection_ebs(
    instance_id: str, block_mapping: list, ec2_client
):
    """
    Update mounted EBS termination behaviour
    """
    device_to_be_updated = [
        {
            "DeviceName": item["DeviceName"],
            "Ebs": {"DeleteOnTermination": False},
        }
        for idx, item in enumerate(block_mapping)
        if "Ebs" in item
    ]
    try:
        logger.info(
            f"Update Delete on termination to false for {instance_id} with request {device_to_be_updated}"
        )
        update_ebs_volume_response = ec2_client.modify_instance_attribute(
            InstanceId=instance_id, BlockDeviceMappings=device_to_be_updated
        )
        logger.info(
            f"Update Delete on termination to false {update_ebs_volume_response}"
        )

    except ClientError as e:
        logger.error(
            "Update Delete on termination to false, proceed to isolate"
        )
        logger.error(e)


def update_profile_for_instance(
    instance_id: str,
    app_account: str,
    forensic_isolation_instance_profile: str,
    ec2_client,
    current_account: str,
):
    """
    Attach isolation profile to isolated instance
    """
    target_profile_name = forensic_isolation_instance_profile
    if app_account == current_account:
        target_profile_name = os.environ[
            "SOLUTION_ACCOUNT_ISOLATION_INSTANCE_PROFILE_NAME"
        ]

    try:
        profile_arn = f"arn arn:aws:iam::{app_account}:instance-profile/{target_profile_name}"
        logger.info(
            f"Update instance profile for {instance_id} with role {profile_arn}"
        )
        iam_instance_profile_associations = (
            ec2_client.describe_iam_instance_profile_associations(
                Filters=[{"Name": "instance-id", "Values": [instance_id]}]
            )["IamInstanceProfileAssociations"]
        )

        if len(iam_instance_profile_associations) > 0:
            # can only max 1
            association_id = iam_instance_profile_associations[0][
                "AssociationId"
            ]
            logger.info(
                f"Update instance profile association {iam_instance_profile_associations} for {instance_id} with role {profile_arn}"
            )
            logger.info(
                f"Test arn {profile_arn} name {target_profile_name} association id  {association_id}"
            )

            ec2_client.replace_iam_instance_profile_association(
                IamInstanceProfile={"Name": target_profile_name},
                AssociationId=association_id,
            )
        else:
            # no profile associated, this should not happen
            # in case it does, we will provide best effort to protect the instance by associate a new profile
            logger.warning(
                f"Existing profile not found for {instance_id} , associating isolating instance profile"
            )
            ec2_client.associate_iam_instance_profile(
                IamInstanceProfile={"Name": target_profile_name},
                InstanceId=instance_id,
            )

    except Exception as e:
        logger.error(
            "Update instance profile fail, non critical failure proceed"
        )
        logger.error(e)
