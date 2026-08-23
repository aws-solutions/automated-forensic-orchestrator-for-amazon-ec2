#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import os
import time
from typing import Any, Dict

import botocore
from arnparse import arnparse
from aws_xray_sdk.core import xray_recorder
from eks_token import get_token
from kubernetes import client, config

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import clean_date_format, create_response
from ..common.log import get_logger
from ..common.redact import redact
from ..common.managed_nodes import describe_node
from ..data.datatypes import Finding, ForensicsProcessingPhase, ResourceType
from ..data.service import ForensicDataService

logger = get_logger(__name__)
# access_role_arn = os.environ['CLUSTER_ACCESS_ROLE_ARN']

# Get Cluster name
# cluster_name = os.environ["CLUSTER_NAME"]
cluster_cache: Dict[str, Any] = {}


@xray_recorder.capture("Forensic Triaging")
def lambda_handler(event, context):
    """
    Get instance info for given triggered event from event bridge
    """

    app_account_role = os.environ["APP_ACCOUNT_ROLE"]

    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
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

    forensic_record, instance_id, instance_account, instance_region = (
        None,
        None,
        None,
        None,
    )

    try:
        # Expecting a Security Hub custom action event
        action_name = get_action_name(event)

        is_triggered_by_fo_security_hub_custom_action(action_name)

        isolation_needed = is_isolation_action(action_name)

        # Is Ec2 instance or EKS cluster in scope for the finding ?
        resource_type = is_ec2_or_eks_in_scope(event)

        if resource_type == "AwsEc2Instance":

            # Is an EC2 Instance resource in scope for the finding?
            is_single_ec2_instance_in_scope(event)

            related_findings = get_related_findings(event)
            logger.info(related_findings)
            instance_id, instance_account, instance_region = (
                get_instance_details(event)
            )

            forensic_record = fds.create_forensic_record(
                resource_type=ResourceType.INSTANCE,
                resource_id=instance_id,
                aws_account_id=instance_account,
                aws_region=instance_region,
                associated_findings=[
                    Finding(
                        finding["finding_id"],
                        finding["product"],
                        finding["region"],
                    )
                    for finding in related_findings
                ],
            )

            logger.info("Retrieve instance info")

            current_account = context.invoked_function_arn.split(":")[4]

            ec2_client = create_aws_client(
                "ec2",
                current_account=current_account,
                target_account=instance_account,
                target_region=instance_region,
                app_account_role=app_account_role,
            )

            instance_info = clean_date_format(
                retrieve_instance_info(logger, ec2_client, instance_id)
            )

            ssm_client = create_aws_client(
                "ssm",
                current_account=current_account,
                target_account=instance_account,
                target_region=instance_region,
                app_account_role=app_account_role,
            )

            instance_platform_info = get_instance_platform(
                ssm_client, instance_id, instance_info
            )

            fds.add_forensic_timeline_event(
                id=forensic_record.id,
                name="Get Instance Info",
                description="Retrieved instance info",
                phase=ForensicsProcessingPhase.TRIAGE,
                component_id="triage",
                component_type="Lambda",
                event_data=instance_platform_info,
            )

            fds.update_forensic_record_resource_info(
                id=forensic_record.id, resource_info=instance_platform_info
            )

            fds.update_forensic_record_phase_status(
                id=forensic_record.id,
                triage=(ForensicsProcessingPhase.SUCCESS, "Completed triage"),
            )

        elif resource_type == "AwsEksCluster":
            cluster_in_scope, event = is_single_eks_cluster_in_scope(event)

            logger.info(f"EKS cluster in scope is {cluster_in_scope}")
            logger.info("Event is %s", redact(event))

            cluster_name, cluster_account, cluster_region = (
                get_cluster_details(event)
            )
            logger.info(
                f"Assuming role in {cluster_account} with region {cluster_region}"
            )
            current_account = context.invoked_function_arn.split(":")[4]
            eks_client = create_aws_client(
                "eks",
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
            app_account_role_arn = (
                f"arn:aws:iam::{cluster_account}:role/{app_account_role}"
            )
            set_cluster_access_mode(
                cluster_name, eks_client, app_account_role_arn
            )
            (
                affected_cluster_resource_type,
                affected_resource_namespace,
                affected_pod_list_resource,
            ) = get_affected_resource_in_cluster(
                event, cluster_name, eks_client, app_account_role_arn
            )

            if affected_cluster_resource_type == "Node":
                affected_node_info = event["detail"]["findings"][0][
                    "Resources"
                ][0]["Details"]["Other"][
                    "kubernetesDetails/kubernetesUserDetails/username"
                ]
                affected_node_ip = (
                    affected_node_info.split(":")[-1]
                    .split(".")[0]
                    .replace("-", ".")
                    .strip("ip.")
                )
                affected_instance_detail = ec2_client.describe_instances(
                    Filters=[
                        {
                            "Name": "private-ip-address",
                            "Values": [affected_node_ip],
                        }
                    ]
                )
                # [id], not list(id). InstanceId is a string, and list() on a
                # string returns its characters: list("i-0abc...") is
                # ['i', '-', '0', 'a', ...], 19 entries. That went into the
                # forensic record as resource_id and then into
                # ForensicInstanceIds, so every downstream acquisition iterated
                # the characters and tried to image instances called "i", "-"
                # and "0". The EKS Node path could not have worked.
                affected_node_list = [
                    affected_instance_detail["Reservations"][0]["Instances"][
                        0
                    ]["InstanceId"]
                ]
            else:
                affected_node_complete_list = get_affected_node_from_pod(
                    cluster_name,
                    affected_pod_list_resource,
                    affected_resource_namespace,
                    eks_client,
                    app_account_role_arn,
                )
                affected_node_list = list(set(affected_node_complete_list))
            related_findings = get_related_findings(event)
            logger.info(related_findings)
            forensic_record = fds.create_forensic_record(
                resource_type=ResourceType.EKS,
                resource_id=affected_node_list,
                aws_account_id=cluster_account,
                aws_region=cluster_region,
                associated_findings=[
                    Finding(
                        finding["finding_id"],
                        finding["product"],
                        finding["region"],
                    )
                    for finding in related_findings
                ],
            )
            affected_instance_info_list = []
            for each_affected_node in affected_node_list:
                instance_info = clean_date_format(
                    retrieve_instance_info(
                        logger, ec2_client, each_affected_node
                    )
                )
                ssm_client = create_aws_client(
                    "ssm",
                    current_account=current_account,
                    target_account=cluster_account,
                    target_region=cluster_region,
                    app_account_role=app_account_role,
                )

                instance_platform_info = get_instance_platform(
                    ssm_client, each_affected_node, instance_info
                )
                affected_instance_info_list.append(instance_platform_info)

            cluster_info = clean_date_format(
                {
                    "clusterName": cluster_name,
                    "affectedResourceType": affected_cluster_resource_type,
                    "affectedPodResource": affected_pod_list_resource,
                    "affectedResourceNamespace": affected_resource_namespace,
                    "affectedNode": affected_node_list,
                    "instanceInfo": affected_instance_info_list,
                }
            )
            fds.add_forensic_timeline_event(
                id=forensic_record.id,
                name="Get Resource Info",
                description="Retrieved EKS Cluster info",
                phase=ForensicsProcessingPhase.TRIAGE,
                component_id="triage",
                component_type="Lambda",
                event_data=cluster_info,
            )

            fds.update_forensic_record_resource_info(
                id=forensic_record.id, resource_info=cluster_info
            )

            fds.update_forensic_record_phase_status(
                id=forensic_record.id,
                triage=(ForensicsProcessingPhase.SUCCESS, "Completed triage"),
            )
        else:
            raise ValueError(f"Invalid supported resource: {resource_type}")
    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }

        logger.error(exception_obj)

        if not forensic_record:
            forensic_record = fds.create_failed_forensic_record(
                event_data=exception_obj
            )
        else:
            fds.add_forensic_timeline_event(
                id=forensic_record.id,
                name="Error: Triaging Instance",
                description="Error while processing Forensic Orchestrator trigger event",
                phase=ForensicsProcessingPhase.TRIAGE,
                component_id="triage",
                component_type="Lambda",
                event_data=exception_obj,
            )

        raise e

    if resource_type == "AwsEc2Instance":
        return create_response(
            200,
            {
                "instanceInfo": instance_platform_info,
                "forensicId": forensic_record.id,
                "instanceAccount": instance_account,
                "instanceRegion": instance_region,
                "isAcquisitionRequired": is_triage_required(
                    instance_platform_info
                ),
                "isIsolationNeeded": isolation_needed,
            },
        )
    elif resource_type == "AwsEksCluster":
        return create_response(
            200,
            {
                "clusterInfo": cluster_info,
                "instanceInfo": affected_instance_info_list,
                "forensicId": forensic_record.id,
                "instanceAccount": cluster_account,
                "instanceRegion": cluster_region,
                "isAcquisitionRequired": is_triage_required_eks(
                    affected_instance_info_list
                ),
                "isIsolationNeeded": isolation_needed,
            },
        )


def get_action_name(event):
    action = event["resources"][0]
    action_array = action.split("/")
    action_name = action_array[len(action_array) - 1]
    return action_name


def is_isolation_action(action_name) -> bool:
    return action_name == "ForensicIsolateAct"


# Function to get the EC2 instance IDs of nodes where the specified pods are running
# Parameters:
#   cluster_name: Name of the EKS cluster
#   affected_pod_list: List of pod names to check
#   namespace: Kubernetes namespace where the pods are running
#   eks_client: boto3 EKS client
#   cluster_admin_role_arn: ARN of cluster admin role for authentication
# Returns:
#   List of EC2 instance IDs where the pods are running
def get_affected_node_from_pod(
    cluster_name,
    affected_pod_list,
    namespace,
    eks_client,
    cluster_admin_role_arn,
):
    logger.info(
        f"Getting instance details from the Pod {affected_pod_list} in Namespace {namespace}"
    )
    get_kubeconfig = get_eks_credentials(
        cluster_name, eks_client, cluster_admin_role_arn
    )
    config.load_kube_config_from_dict(config_dict=get_kubeconfig)
    api_instance = client.CoreV1Api()
    affected_instance_id = []
    for affected_pod in affected_pod_list:
        pod_info = api_instance.read_namespaced_pod(
            name=affected_pod, namespace=namespace
        )
        node_name = pod_info.spec.node_name
        node_info = api_instance.read_node(name=node_name)
        instance_pid = node_info.spec.provider_id
        affected_instance_id.append(instance_pid.split("/")[-1])

    return affected_instance_id


def is_triggered_by_fo_security_hub_custom_action(action_name):

    if action_name not in [
        "TriageAction",
        "TriageIsolationAction",
        "ForensicTriageAction",
        "ForensicIsolateAct",
    ]:
        logger.warning(f"Invalid event name: {action_name}")
        raise ValueError(f"Invalid event name: {action_name}")


def is_ec2_or_eks_in_scope(event):
    findings = event["detail"]["findings"]
    resource_types = []
    for finding in findings:
        for resource in finding["Resources"]:
            resource_types.append(resource["Type"])
    if not resource_types:
        raise ValueError(f"Invalid trigger event: {event}")
    for each_resource in resource_types:
        if each_resource not in ["AwsEc2Instance", "AwsEksCluster"]:
            resource_types.remove(each_resource)
    if len(resource_types) > 1:
        raise ValueError(
            f"More than one instance or EKS cluster in-scope for event: {event}"
        )
    return resource_types[0]


def is_single_ec2_instance_in_scope(event):
    findings = event["detail"]["findings"]
    instances = []

    for finding in findings:
        instances.extend(
            [
                resource
                for resource in finding["Resources"]
                if resource.get("Type") == "AwsEc2Instance"
            ]
        )

    if not instances:
        raise ValueError(f"Invalid trigger event: {event}")

    if len(instances) > 1:
        raise ValueError(f"More than one instance in-scope for event: {event}")

    return instances


def is_single_eks_cluster_in_scope(event):
    findings = event["detail"]["findings"]
    eksclusters = []

    for finding in findings:
        eksclusters.extend(
            [
                resource
                for resource in finding["Resources"]
                if resource.get("Type") == "AwsEksCluster"
            ]
        )

    filtered_resources = [
        resource
        for resource in event["detail"]["findings"][0]["Resources"]
        if resource.get("Type") == "AwsEksCluster"
    ]
    event["detail"]["findings"][0]["Resources"] = filtered_resources
    if not eksclusters:
        raise ValueError(f"Invalid trigger event: {event}")

    if len(eksclusters) > 1:
        raise ValueError(f"More than one instance in-scope for event: {event}")

    return eksclusters, event


def get_cluster_details(event):
    cluster_arn = event["detail"]["findings"][0]["Resources"][0]["Id"]
    logger.info(cluster_arn)
    parsed_arn = arnparse(cluster_arn)
    eks_cluster_name = parsed_arn.resource
    eks_cluster_account = parsed_arn.account_id
    eks_cluster_region = parsed_arn.region
    if not eks_cluster_name:
        raise ValueError(
            "The EKS cluster name is missing in trigger event: {0}".format(
                event
            )
        )

    return eks_cluster_name, eks_cluster_account, eks_cluster_region


# This function sets the access mode for an EKS cluster and adds access entry for the admin role
# https://aws.amazon.com/blogs/containers/a-deep-dive-into-simplified-amazon-eks-access-management-controls/
def set_cluster_access_mode(clustername, eks_client, cluster_admin_role_arn):
    cluster_describe_response = eks_client.describe_cluster(name=clustername)
    access_mode = cluster_describe_response["cluster"]["accessConfig"][
        "authenticationMode"
    ]
    logger.info(f"Access mode of cluster {clustername}: {access_mode}")
    try:
        if access_mode == "CONFIG_MAP":
            logger.info(
                "Access mode is CONFIG_MAP. hence updating it to API_CONFIG_MAP."
            )
            eks_client.update_cluster_config(
                name=clustername,
                accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
            )
            get_add_access_entry(
                clustername, eks_client, cluster_admin_role_arn
            )

        elif access_mode == "API" or access_mode == "API_AND_CONFIG_MAP":
            get_add_access_entry(
                clustername, eks_client, cluster_admin_role_arn
            )
        else:
            raise ValueError(f"Invalid access mode {access_mode}")
    except botocore.exceptions.ClientError as error:
        logger.error(f"Adding the access entry failed due to Error: {error}")
        raise error


# Add ClusterAdmin Access Entry for the Cluster Admin Role .
def get_add_access_entry(clustername, eks_client, cluster_admin_role_arn):
    logger.info(
        "Validating if access entry already exist for the role on the cluster."
    )
    list_access_entries = eks_client.list_access_entries(
        clusterName=clustername,
        associatedPolicyArn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
    )
    if cluster_admin_role_arn in list_access_entries["accessEntries"]:
        logger.info("Access entry already exist for the role on the cluster.")
        pass
    else:
        # Adding the Role ARN to the cluster
        logger.info(
            f"Adding the role ARN: {cluster_admin_role_arn} to the cluster."
        )
        eks_client.create_access_entry(
            clusterName=clustername, principalArn=cluster_admin_role_arn
        )
        eks_client.associate_access_policy(
            clusterName=clustername,
            principalArn=cluster_admin_role_arn,
            policyArn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
            accessScope={
                "type": "cluster",
            },
        )
        list_access_entries = eks_client.list_access_entries(
            clusterName=clustername,
            associatedPolicyArn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
        )
        # Check if the cluster admin role is added to entry if not sleep for 100
        while (
            cluster_admin_role_arn not in list_access_entries["accessEntries"]
        ):
            logger.info(
                "Access entry is not added to the cluster. Sleeping for 100 seconds."
            )
            time.sleep(100)
            list_access_entries = eks_client.list_access_entries(
                clusterName=clustername,
                associatedPolicyArn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
            )
            if cluster_admin_role_arn in list_access_entries["accessEntries"]:
                logger.info(
                    "Access entry is added to the cluster. Continuing the execution."
                )
                break
            else:
                logger.info(
                    "Access entry is not added to the cluster. Sleeping for 100 seconds."
                )
                continue


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


def get_affected_pods(
    type,
    cluster_name,
    affected_resource,
    affected_resource_namespace,
    eks_client,
    cluster_admin_role_arn,
):
    get_kubeconfig = get_eks_credentials(
        cluster_name, eks_client, cluster_admin_role_arn
    )
    config.load_kube_config_from_dict(config_dict=get_kubeconfig)
    app_api_instance = client.AppsV1Api()
    api_instance = client.CoreV1Api()
    affected_pods = []
    if type == "Deployment":
        # Get the deployment details
        deployment_details = app_api_instance.read_namespaced_deployment(
            name=affected_resource, namespace=affected_resource_namespace
        )
        label_selector = deployment_details.spec.selector.match_labels

        # Get the pods with the same label selector
        label_string = ""
        for key, value in label_selector.items():
            label_string += f"{key}={value},"
        pod_label_selector = label_string.rstrip(",")

        affected_pods_details = api_instance.list_pod_for_all_namespaces(
            label_selector=pod_label_selector
        )

        affected_pods_list = affected_pods_details.items
        for each_pod in affected_pods_list:
            affected_pods.append(each_pod.metadata.name)
    elif type == "ServiceAccount":
        # Get Service account details
        pod_details_namespace = api_instance.list_namespaced_pod(
            namespace=affected_resource_namespace
        )
        for each_pod in pod_details_namespace.items:
            # pod_details = api_instance.read_namespaced_pod(
            #     namespace=affected_resource_namespace,
            #     name=each_pod.metadata.name,
            # )
            if each_pod.spec.service_account == affected_resource:
                affected_pods.append(each_pod.metadata.name)
    else:
        logger.error("Unsupported resource type")
        raise Exception("Unsupported resource type")
    return affected_pods


def get_affected_resource_in_cluster(
    event, clustername, eks_client, cluster_admin_role_arn
):
    """
    Determines affected Kubernetes resources based on GuardDuty finding event.

    Args:
        event (dict): GuardDuty finding event containing details about the affected resource
        clustername (str): Name of the EKS cluster
        eks_client: AWS EKS client object
        cluster_admin_role_arn (str): ARN of cluster admin role for authentication

    Returns:
        tuple: Contains:
            - affected_resource_type (str): Type of affected resource (ServiceAccount/Node/Deployment/Pods/none)
            - affected_resource_namespace (str): Namespace of affected pods
            - affected_pod (list): List of affected pod names

    Handles different resource types:
    - Service accounts
    - Nodes
    - Deployments
    - Individual pods
    """
    user_detail = event["detail"]["findings"][0]["Resources"][0]["Details"][
        "Other"
    ]["kubernetesDetails/kubernetesUserDetails/username"]
    if "serviceaccount" in user_detail:
        logger.info(
            "Service account detected, triggering service account rollout"
        )
        affected_resource_type = "ServiceAccount"
        service_account_name_detail = event["detail"]["findings"][0][
            "Resources"
        ][0]["Details"]["Other"][
            "kubernetesDetails/kubernetesUserDetails/username"
        ]
        service_account = service_account_name_detail.split(":")[-1]
        affected_resource_namespace = service_account_name_detail.split(":")[
            -2
        ]
        affected_pod = get_affected_pods(
            affected_resource_type,
            clustername,
            service_account,
            affected_resource_namespace,
            eks_client,
            cluster_admin_role_arn,
        )
    elif "system:node" in user_detail:
        logger.info("Entire node is impacted")
        affected_resource_type = "Node"
        affected_pod = []
        affected_resource_namespace = "none"
    else:
        affected_resource_type = event["detail"]["findings"][0]["Resources"][
            0
        ]["Details"]["Other"][
            "kubernetesDetails/kubernetesWorkloadDetails/type"
        ].lower()
        # `x == "deployments" or "deployment"` is always true: the second
        # operand is a non-empty string literal, not a comparison. Every
        # workload finding therefore took the Deployment branch and the Pods
        # branch below was unreachable, so a Pods finding was looked up as a
        # deployment name and matched nothing.
        if affected_resource_type in ("deployments", "deployment"):
            logger.info("Deployment resource detected")
            affected_resource_type = "Deployment"
            affected_deployment = event["detail"]["findings"][0]["Resources"][
                0
            ]["Details"]["Other"][
                "kubernetesDetails/kubernetesWorkloadDetails/name"
            ]
            affected_resource_namespace = event["detail"]["findings"][0][
                "Resources"
            ][0]["Details"]["Other"][
                "kubernetesDetails/kubernetesWorkloadDetails/namespace"
            ]
            affected_pod = get_affected_pods(
                affected_resource_type,
                clustername,
                affected_deployment,
                affected_resource_namespace,
                eks_client,
                cluster_admin_role_arn,
            )

        elif affected_resource_type == "pods":
            logger.info("Pods resource detected")
            affected_resource_type = "Pods"
            affected_pod = event["detail"]["findings"][0]["Resources"][0][
                "Details"
            ]["Other"][
                "kubernetesDetails/kubernetesWorkloadDetails/name"
            ].split(
                " "
            )
            affected_resource_namespace = event["detail"]["findings"][0][
                "Resources"
            ][0]["Details"]["Other"][
                "kubernetesDetails/kubernetesWorkloadDetails/namespace"
            ]

        else:
            affected_resource_type = "none"
            affected_pod = []
            affected_resource_namespace = "none"
            logger.info("No rollout triggered")

    return affected_resource_type, affected_resource_namespace, affected_pod


def get_instance_details(event):
    resource_arn = event["detail"]["findings"][0]["Resources"][0]["Id"]
    logger.info(resource_arn)

    parsed_arn = arnparse(resource_arn)
    ec2_instance_id = parsed_arn.resource
    ec2_instance_account = parsed_arn.account_id
    ec2_instance_region = parsed_arn.region

    if not ec2_instance_id:
        raise ValueError(
            "The EC2 Instance ID is missing in trigger event: {0}".format(
                event
            )
        )

    return ec2_instance_id, ec2_instance_account, ec2_instance_region


def get_related_findings(event):
    findings = event["detail"]["findings"]
    related_findings = []

    for finding in findings:
        related_findings.append(
            {
                "finding_id": (
                    finding.get("Id")
                    if finding.get("ProductName") == "Security Hub"
                    else finding.get("GeneratorId")
                ),
                "product": finding.get("ProductName"),
                "region": finding.get("Region"),
                "account": finding.get("AwsAccountId"),
            }
        )

    return related_findings


def is_triage_required(instance_info) -> bool:
    try:
        explicit_triage_set = any(
            element.get("Key") == "IsTriageRequired"
            and element.get("Value") == "True"
            for element in instance_info["Tags"]
        )
        no_triage_tag_present = all(
            element.get("Key") != "IsTriageRequired"
            for element in instance_info["Tags"]
        )
        return explicit_triage_set or no_triage_tag_present
    except Exception as e:
        logger.error(f"No tags found in the instance {e}")
        return True


def is_triage_required_eks(instance_info):
    try:
        triage_required_dict: Dict[str, bool] = {}
        for each_instance in instance_info:
            explicit_triage_set = any(
                element.get("Key") == "IsTriageRequired"
                and element.get("Value") == "True"
                for element in each_instance["Tags"]
            )
            no_triage_tag_present = all(
                element.get("Key") != "IsTriageRequired"
                for element in each_instance["Tags"]
            )
            triage_required_dict[each_instance["InstanceId"]] = (
                explicit_triage_set or no_triage_tag_present
            )
        return triage_required_dict
    except Exception as e:
        logger.error(f"No tags found in the instance {e}")
        return True


def retrieve_instance_info(logger, ec2_client, instance_id: str):
    logger.info("retrieve_instance_info_list")

    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    logger.info("retrieve_instance_info")

    logger.info("ec2 instance raw response %s", response)
    if not response["Reservations"][0]["Instances"]:
        logger.error(
            f"Error while retrieving instance info for: {instance_id}"
        )
        raise ValueError("No associated instance info available: ")
    return response["Reservations"][0]["Instances"][0]


def get_instance_platform(ssm_client, instance_id: str, instance_info: dict):
    # Paginated via the shared lookup. Filtering alone is not enough: an empty
    # first page carrying a NextToken is a permitted response, and reading only
    # that page raised "not able to accuire instance detail info" for an instance
    # that was registered - which fails triage before any evidence is taken.
    node = describe_node(ssm_client, instance_id)
    if node is None:
        raise Exception(
            f"{instance_id} is not registered with Systems Manager, so its "
            "platform cannot be determined and no document can be selected"
        )
    platform_type = node.get("PlatformType", "")
    platform_name = node.get("PlatformName", "")
    platform_version = node.get("PlatformVersion", "")

    instance_info["PlatformType"] = platform_type
    instance_info["PlatformName"] = platform_name
    instance_info["PlatformVersion"] = platform_version
    logger.info("Retrieved instance info {0}".format(instance_info))
    return instance_info


# def retrieve_instance_info_eks(logger, ec2_client, instance_id_list: list):
#     logger.info("retrieve_instance_info_list")
#     instance_id_info_list = []
#     for instance_id in instance_id_list:
#         response = ec2_client.describe_instances(InstanceIds=[instance_id])
#         logger.info("retrieve_instance_info2")

#         logger.info("ec2 instance raw response %s", response)
#         if not response["Reservations"][0]["Instances"]:
#             logger.error(
#                 f"Error while retrieving instance info for: {instance_id}"
#             )
#             raise ValueError("No associated instance info available: ")

#         instance_id_info_list.append(response["Reservations"][0]["Instances"][0])
#     return instance_id_info_list
