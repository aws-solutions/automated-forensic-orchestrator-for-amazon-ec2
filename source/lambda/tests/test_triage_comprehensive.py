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
from unittest import mock
from unittest.mock import MagicMock, Mock, call, patch

import botocore
import pytest
from kubernetes import client

from ..src.triage import app


class TestTriageHelperFunctions:
    """Test helper functions in triage app"""

    def test_get_action_name(self):
        """Test extracting action name from event"""
        event = {
            "resources": [
                "arn:aws:securityhub:region:account:action/custom/ForensicTriageAction"
            ]
        }
        result = app.get_action_name(event)
        assert result == "ForensicTriageAction"

    def test_is_isolation_action_true(self):
        """Test isolation action detection - positive case"""
        assert app.is_isolation_action("ForensicIsolateAct") is True

    def test_is_isolation_action_false(self):
        """Test isolation action detection - negative case"""
        assert app.is_isolation_action("ForensicTriageAction") is False

    def test_is_triggered_by_fo_security_hub_custom_action_valid(self):
        """Test valid action names"""
        valid_actions = [
            "TriageAction",
            "TriageIsolationAction",
            "ForensicTriageAction",
            "ForensicIsolateAct",
        ]
        for action in valid_actions:
            # Should not raise exception
            app.is_triggered_by_fo_security_hub_custom_action(action)

    def test_is_triggered_by_fo_security_hub_custom_action_invalid(self):
        """Test invalid action name raises ValueError"""
        with pytest.raises(ValueError, match="Invalid event name"):
            app.is_triggered_by_fo_security_hub_custom_action("InvalidAction")


class TestResourceTypeValidation:
    """Test resource type validation functions"""

    def test_is_ec2_or_eks_in_scope_ec2(self):
        """Test EC2 resource type detection"""
        event = {
            "detail": {
                "findings": [{"Resources": [{"Type": "AwsEc2Instance"}]}]
            }
        }
        result = app.is_ec2_or_eks_in_scope(event)
        assert result == "AwsEc2Instance"

    def test_is_ec2_or_eks_in_scope_eks(self):
        """Test EKS resource type detection"""
        event = {
            "detail": {
                "findings": [{"Resources": [{"Type": "AwsEksCluster"}]}]
            }
        }
        result = app.is_ec2_or_eks_in_scope(event)
        assert result == "AwsEksCluster"

    def test_is_ec2_or_eks_in_scope_no_resources(self):
        """Test empty resources raises ValueError"""
        event = {"detail": {"findings": [{"Resources": []}]}}
        with pytest.raises(ValueError, match="Invalid trigger event"):
            app.is_ec2_or_eks_in_scope(event)

    def test_is_ec2_or_eks_in_scope_multiple_resources(self):
        """Test multiple resources raises ValueError"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {"Type": "AwsEc2Instance"},
                            {"Type": "AwsEksCluster"},
                        ]
                    }
                ]
            }
        }
        with pytest.raises(
            ValueError, match="More than one instance or EKS cluster"
        ):
            app.is_ec2_or_eks_in_scope(event)

    def test_is_ec2_or_eks_in_scope_unsupported_resource(self):
        """Test unsupported resource type"""
        event = {
            "detail": {"findings": [{"Resources": [{"Type": "AwsS3Bucket"}]}]}
        }
        # Should filter out unsupported resources and raise IndexError when accessing empty list
        with pytest.raises(IndexError):
            app.is_ec2_or_eks_in_scope(event)


class TestEC2InstanceValidation:
    """Test EC2 instance validation functions"""

    def test_is_single_ec2_instance_in_scope_valid(self):
        """Test single EC2 instance validation"""
        event = {
            "detail": {
                "findings": [
                    {"Resources": [{"Type": "AwsEc2Instance", "Id": "i-123"}]}
                ]
            }
        }
        result = app.is_single_ec2_instance_in_scope(event)
        assert len(result) == 1
        assert result[0]["Type"] == "AwsEc2Instance"

    def test_is_single_ec2_instance_in_scope_no_instances(self):
        """Test no EC2 instances raises ValueError"""
        event = {
            "detail": {"findings": [{"Resources": [{"Type": "AwsS3Bucket"}]}]}
        }
        with pytest.raises(ValueError, match="Invalid trigger event"):
            app.is_single_ec2_instance_in_scope(event)

    def test_is_single_ec2_instance_in_scope_multiple_instances(self):
        """Test multiple EC2 instances raises ValueError"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {"Type": "AwsEc2Instance", "Id": "i-123"},
                            {"Type": "AwsEc2Instance", "Id": "i-456"},
                        ]
                    }
                ]
            }
        }
        with pytest.raises(
            ValueError, match="More than one instance in-scope"
        ):
            app.is_single_ec2_instance_in_scope(event)


class TestEKSClusterValidation:
    """Test EKS cluster validation functions"""

    def test_is_single_eks_cluster_in_scope_valid(self):
        """Test single EKS cluster validation"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {"Type": "AwsEksCluster", "Id": "cluster-arn"},
                            {
                                "Type": "AwsS3Bucket",
                                "Id": "bucket-arn",
                            },  # Should be filtered out
                        ]
                    }
                ]
            }
        }
        result, modified_event = app.is_single_eks_cluster_in_scope(event)
        assert len(result) == 1
        assert result[0]["Type"] == "AwsEksCluster"
        # Check that event was modified to only include EKS resources
        assert len(modified_event["detail"]["findings"][0]["Resources"]) == 1

    def test_is_single_eks_cluster_in_scope_no_clusters(self):
        """Test no EKS clusters raises ValueError"""
        event = {
            "detail": {"findings": [{"Resources": [{"Type": "AwsS3Bucket"}]}]}
        }
        with pytest.raises(ValueError, match="Invalid trigger event"):
            app.is_single_eks_cluster_in_scope(event)

    def test_is_single_eks_cluster_in_scope_multiple_clusters(self):
        """Test multiple EKS clusters raises ValueError"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {"Type": "AwsEksCluster", "Id": "cluster1"},
                            {"Type": "AwsEksCluster", "Id": "cluster2"},
                        ]
                    }
                ]
            }
        }
        with pytest.raises(
            ValueError, match="More than one instance in-scope"
        ):
            app.is_single_eks_cluster_in_scope(event)


class TestInstanceDetailsExtraction:
    """Test instance and cluster details extraction"""

    def test_get_instance_details(self):
        """Test extracting instance details from event"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
                            }
                        ]
                    }
                ]
            }
        }
        instance_id, account, region = app.get_instance_details(event)
        assert instance_id == "i-1234567890abcdef0"
        assert account == "123456789012"
        assert region == "us-east-1"

    def test_get_instance_details_missing_id(self):
        """Test missing instance ID raises ValueError"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Id": "arn:aws:ec2:us-east-1:123456789012:invalid/"
                            }
                        ]
                    }
                ]
            }
        }
        with pytest.raises(ValueError, match="The EC2 Instance ID is missing"):
            app.get_instance_details(event)

    def test_get_cluster_details(self):
        """Test extracting cluster details from event"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Id": "arn:aws:eks:us-west-2:123456789012:cluster/my-cluster"
                            }
                        ]
                    }
                ]
            }
        }
        cluster_name, account, region = app.get_cluster_details(event)
        assert cluster_name == "my-cluster"
        assert account == "123456789012"
        assert region == "us-west-2"

    def test_get_cluster_details_missing_name(self):
        """Test missing cluster name raises ValueError"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Id": "arn:aws:eks:us-west-2:123456789012:invalid/"
                            }
                        ]
                    }
                ]
            }
        }
        with pytest.raises(
            ValueError, match="The EKS cluster name is missing"
        ):
            app.get_cluster_details(event)


class TestRelatedFindings:
    """Test related findings extraction"""

    def test_get_related_findings(self):
        """Test extracting related findings"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Id": "finding-1",
                        "GeneratorId": "generator-1",
                        "ProductName": "Security Hub",
                        "Region": "us-east-1",
                        "AwsAccountId": "123456789012",
                    },
                    {
                        "Id": "finding-2",
                        "GeneratorId": "generator-2",
                        "ProductName": "GuardDuty",
                        "Region": "us-west-2",
                        "AwsAccountId": "123456789012",
                    },
                ]
            }
        }
        findings = app.get_related_findings(event)
        assert len(findings) == 2
        assert findings[0]["finding_id"] == "finding-1"  # Security Hub uses Id
        assert (
            findings[1]["finding_id"] == "generator-2"
        )  # Others use GeneratorId


class TestTriageRequiredLogic:
    """Test triage requirement logic"""

    def test_is_triage_required_explicit_true(self):
        """Test explicit triage required tag"""
        instance_info = {
            "Tags": [
                {"Key": "IsTriageRequired", "Value": "True"},
                {"Key": "Environment", "Value": "prod"},
            ]
        }
        assert app.is_triage_required(instance_info) is True

    def test_is_triage_required_explicit_false(self):
        """Test explicit triage not required tag"""
        instance_info = {
            "Tags": [
                {"Key": "IsTriageRequired", "Value": "False"},
                {"Key": "Environment", "Value": "prod"},
            ]
        }
        assert app.is_triage_required(instance_info) is False

    def test_is_triage_required_no_tag(self):
        """Test no triage tag defaults to required"""
        instance_info = {"Tags": [{"Key": "Environment", "Value": "prod"}]}
        assert app.is_triage_required(instance_info) is True

    def test_is_triage_required_no_tags(self):
        """Test no tags at all defaults to required"""
        instance_info = {"Tags": []}
        assert app.is_triage_required(instance_info) is True

    def test_is_triage_required_exception(self):
        """Test exception handling returns True"""
        instance_info = {}  # Missing Tags key
        assert app.is_triage_required(instance_info) is True

    def test_is_triage_required_eks(self):
        """Test EKS triage requirement logic"""
        instance_info_list = [
            {
                "InstanceId": "i-123",
                "Tags": [{"Key": "IsTriageRequired", "Value": "True"}],
            },
            {
                "InstanceId": "i-456",
                "Tags": [{"Key": "Environment", "Value": "prod"}],
            },
        ]
        result = app.is_triage_required_eks(instance_info_list)
        assert result["i-123"] is True
        assert result["i-456"] is True

    def test_is_triage_required_eks_exception(self):
        """Test EKS triage requirement exception handling"""
        instance_info_list = [{}]  # Missing required fields
        result = app.is_triage_required_eks(instance_info_list)
        assert result is True


class TestInstanceInfoRetrieval:
    """Test instance information retrieval"""

    def test_retrieve_instance_info_success(self):
        """Test successful instance info retrieval"""
        logger = MagicMock()
        ec2_client = MagicMock()
        instance_data = {"InstanceId": "i-123", "State": {"Name": "running"}}
        ec2_client.describe_instances.return_value = {
            "Reservations": [{"Instances": [instance_data]}]
        }

        result = app.retrieve_instance_info(logger, ec2_client, "i-123")
        assert result == instance_data
        ec2_client.describe_instances.assert_called_once_with(
            InstanceIds=["i-123"]
        )

    def test_retrieve_instance_info_no_instances(self):
        """Test no instances found raises ValueError"""
        logger = MagicMock()
        ec2_client = MagicMock()
        ec2_client.describe_instances.return_value = {
            "Reservations": [{"Instances": []}]
        }

        with pytest.raises(
            ValueError, match="No associated instance info available"
        ):
            app.retrieve_instance_info(logger, ec2_client, "i-123")

    def test_get_instance_platform_success(self):
        """Test successful platform info retrieval.

        The lookup paginates and matches the record by instance id, so the
        fixture has to carry InstanceId - which is the point: a record for some
        other instance must not be used to pick this instance's documents.
        """
        ssm_client = MagicMock()
        ssm_client.get_paginator.return_value.paginate.return_value = [
            {
                "InstanceInformationList": [
                    {
                        "InstanceId": "i-123",
                        "PlatformType": "Linux",
                        "PlatformName": "Amazon Linux",
                        "PlatformVersion": "2",
                    }
                ]
            }
        ]

        instance_info = {"InstanceId": "i-123"}
        result = app.get_instance_platform(ssm_client, "i-123", instance_info)

        assert result["PlatformType"] == "Linux"
        assert result["PlatformName"] == "Amazon Linux"
        assert result["PlatformVersion"] == "2"

    def test_get_instance_platform_ignores_another_instances_record(self):
        """A page can hold records this call did not ask about."""
        ssm_client = MagicMock()
        ssm_client.get_paginator.return_value.paginate.return_value = [
            {
                "InstanceInformationList": [
                    {
                        "InstanceId": "i-999",
                        "PlatformType": "Windows",
                        "PlatformName": "Microsoft Windows Server",
                        "PlatformVersion": "10.0.17763",
                    }
                ]
            }
        ]
        with pytest.raises(Exception, match="not registered with Systems Manager"):
            app.get_instance_platform(ssm_client, "i-123", {})

    def test_get_instance_platform_no_info(self):
        """Test no platform info raises exception"""
        ssm_client = MagicMock()
        ssm_client.get_paginator.return_value.paginate.return_value = [
            {"InstanceInformationList": []}
        ]

        with pytest.raises(
            Exception, match="not registered with Systems Manager"
        ):
            app.get_instance_platform(ssm_client, "i-123", {})


class TestEKSClusterAccess:
    """Test EKS cluster access management"""

    def test_set_cluster_access_mode_config_map(self):
        """Test updating cluster access mode from CONFIG_MAP"""
        eks_client = MagicMock()
        eks_client.describe_cluster.return_value = {
            "cluster": {"accessConfig": {"authenticationMode": "CONFIG_MAP"}}
        }
        eks_client.list_access_entries.return_value = {"accessEntries": []}

        with patch.object(app, "get_add_access_entry") as mock_add_entry:
            app.set_cluster_access_mode("test-cluster", eks_client, "role-arn")

            eks_client.update_cluster_config.assert_called_once()
            mock_add_entry.assert_called_once()

    def test_set_cluster_access_mode_api(self):
        """Test cluster with API access mode"""
        eks_client = MagicMock()
        eks_client.describe_cluster.return_value = {
            "cluster": {"accessConfig": {"authenticationMode": "API"}}
        }

        with patch.object(app, "get_add_access_entry") as mock_add_entry:
            app.set_cluster_access_mode("test-cluster", eks_client, "role-arn")

            eks_client.update_cluster_config.assert_not_called()
            mock_add_entry.assert_called_once()

    def test_set_cluster_access_mode_invalid(self):
        """Test invalid access mode raises ValueError"""
        eks_client = MagicMock()
        eks_client.describe_cluster.return_value = {
            "cluster": {"accessConfig": {"authenticationMode": "INVALID"}}
        }

        with pytest.raises(ValueError, match="Invalid access mode"):
            app.set_cluster_access_mode("test-cluster", eks_client, "role-arn")

    def test_set_cluster_access_mode_client_error(self):
        """Test client error handling"""
        eks_client = MagicMock()
        eks_client.describe_cluster.return_value = {
            "cluster": {"accessConfig": {"authenticationMode": "API"}}
        }
        error = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied"}}, "operation"
        )

        with patch.object(app, "get_add_access_entry", side_effect=error):
            with pytest.raises(botocore.exceptions.ClientError):
                app.set_cluster_access_mode(
                    "test-cluster", eks_client, "role-arn"
                )

    def test_get_add_access_entry_existing(self):
        """Test access entry already exists"""
        eks_client = MagicMock()
        role_arn = "arn:aws:iam::123456789012:role/test-role"
        eks_client.list_access_entries.return_value = {
            "accessEntries": [role_arn]
        }

        app.get_add_access_entry("test-cluster", eks_client, role_arn)

        eks_client.create_access_entry.assert_not_called()
        eks_client.associate_access_policy.assert_not_called()

    def test_get_add_access_entry_new(self):
        """Test creating new access entry"""
        eks_client = MagicMock()
        role_arn = "arn:aws:iam::123456789012:role/test-role"
        # First call returns empty, second call returns the role
        eks_client.list_access_entries.side_effect = [
            {"accessEntries": []},
            {"accessEntries": [role_arn]},
        ]

        app.get_add_access_entry("test-cluster", eks_client, role_arn)

        eks_client.create_access_entry.assert_called_once()
        eks_client.associate_access_policy.assert_called_once()


class TestEKSClusterInfo:
    """Test EKS cluster information retrieval"""

    def test_get_cluster_info_success(self):
        """Test successful cluster info retrieval"""
        eks_client = MagicMock()
        cluster_data = {
            "cluster": {
                "endpoint": "https://test.eks.amazonaws.com",
                "certificateAuthority": {"data": "cert-data"},
                "arn": "arn:aws:eks:region:account:cluster/test",
            }
        }
        eks_client.describe_cluster.return_value = cluster_data

        result = app.get_cluster_info("test-cluster", eks_client)

        assert result["endpoint"] == "https://test.eks.amazonaws.com"
        assert result["ca"] == "cert-data"
        assert result["name"] == "arn:aws:eks:region:account:cluster/test"

    def test_get_cluster_info_client_error(self):
        """Test cluster info retrieval error"""
        eks_client = MagicMock()
        error = botocore.exceptions.ClientError(
            {"Error": {"Code": "ClusterNotFound"}}, "describe_cluster"
        )
        eks_client.describe_cluster.side_effect = error

        with pytest.raises(botocore.exceptions.ClientError):
            app.get_cluster_info("test-cluster", eks_client)

    def test_get_bearer_token_mock(self):
        """Test bearer token function exists and can be called"""
        # This function requires real AWS credentials, so we just test it exists
        assert hasattr(app, "get_bearer_token")
        assert callable(app.get_bearer_token)

    @patch.object(app, "get_cluster_info")
    @patch.object(app, "get_bearer_token")
    def test_get_eks_credentials_cached(self, mock_bearer, mock_cluster_info):
        """Test EKS credentials with cached cluster info"""
        # Setup cache
        app.cluster_cache["test-cluster"] = {
            "endpoint": "https://test.eks.amazonaws.com",
            "ca": "cert-data",
            "name": "cluster-arn",
        }
        mock_bearer.return_value = {"status": {"token": "test-token"}}

        result = app.get_eks_credentials("test-cluster", None, "role-arn")

        assert result["kind"] == "Config"
        assert result["current-context"] == "lambda-kubectl-context"
        mock_cluster_info.assert_not_called()  # Should use cache
        mock_bearer.assert_called_once()

    @patch.object(app, "get_cluster_info")
    @patch.object(app, "get_bearer_token")
    def test_get_eks_credentials_not_cached(
        self, mock_bearer, mock_cluster_info
    ):
        """Test EKS credentials without cached cluster info"""
        # Clear cache
        app.cluster_cache.clear()

        mock_cluster_info.return_value = {
            "endpoint": "https://test.eks.amazonaws.com",
            "ca": "cert-data",
            "name": "cluster-arn",
        }
        mock_bearer.return_value = {"status": {"token": "test-token"}}

        result = app.get_eks_credentials("test-cluster", None, "role-arn")

        assert result["kind"] == "Config"
        mock_cluster_info.assert_called_once()
        mock_bearer.assert_called_once()
        # Should cache the result
        assert "test-cluster" in app.cluster_cache


class TestKubernetesResourceHandling:
    """Test Kubernetes resource handling functions"""

    @patch("kubernetes.config.load_kube_config_from_dict")
    @patch("kubernetes.client.AppsV1Api")
    @patch("kubernetes.client.CoreV1Api")
    @patch.object(app, "get_eks_credentials")
    def test_get_affected_pods_deployment(
        self, mock_creds, mock_core_api, mock_apps_api, mock_config
    ):
        """Test getting affected pods for deployment"""
        # Setup mocks
        mock_creds.return_value = {"test": "config"}

        mock_deployment = MagicMock()
        mock_deployment.spec.selector.match_labels = {"app": "test-app"}
        mock_apps_api.return_value.read_namespaced_deployment.return_value = (
            mock_deployment
        )

        mock_pod = MagicMock()
        mock_pod.metadata.name = "test-pod-1"
        mock_core_api.return_value.list_pod_for_all_namespaces.return_value.items = [
            mock_pod
        ]

        result = app.get_affected_pods(
            "Deployment",
            "test-cluster",
            "test-deployment",
            "default",
            None,
            "role-arn",
        )

        assert result == ["test-pod-1"]
        mock_apps_api.return_value.read_namespaced_deployment.assert_called_once()

    @patch("kubernetes.config.load_kube_config_from_dict")
    @patch("kubernetes.client.CoreV1Api")
    @patch.object(app, "get_eks_credentials")
    def test_get_affected_pods_service_account(
        self, mock_creds, mock_core_api, mock_config
    ):
        """Test getting affected pods for service account"""
        # Setup mocks
        mock_creds.return_value = {"test": "config"}

        mock_pod = MagicMock()
        mock_pod.metadata.name = "test-pod-1"
        mock_pod.spec.service_account = "test-sa"
        mock_core_api.return_value.list_namespaced_pod.return_value.items = [
            mock_pod
        ]

        result = app.get_affected_pods(
            "ServiceAccount",
            "test-cluster",
            "test-sa",
            "default",
            None,
            "role-arn",
        )

        assert result == ["test-pod-1"]

    @patch("kubernetes.config.load_kube_config_from_dict")
    @patch.object(app, "get_eks_credentials")
    def test_get_affected_pods_unsupported_type(self, mock_creds, mock_config):
        """Test unsupported resource type raises exception"""
        mock_creds.return_value = {
            "apiVersion": "v1",
            "current-context": "test-context",
            "contexts": [{"name": "test-context"}],
            "clusters": [{"name": "test-cluster"}],
            "users": [{"name": "test-user"}],
        }

        with pytest.raises(Exception, match="Unsupported resource type"):
            app.get_affected_pods(
                "UnsupportedType",
                "test-cluster",
                "resource",
                "default",
                None,
                "arn:aws:iam::123456789012:role/test-role",
            )

    @patch("kubernetes.config.load_kube_config_from_dict")
    @patch("kubernetes.client.CoreV1Api")
    @patch.object(app, "get_eks_credentials")
    def test_get_affected_node_from_pod(
        self, mock_creds, mock_core_api, mock_config
    ):
        """Test getting affected nodes from pods"""
        # Setup mocks
        mock_creds.return_value = {"test": "config"}

        mock_pod = MagicMock()
        mock_pod.spec.node_name = "test-node"
        mock_core_api.return_value.read_namespaced_pod.return_value = mock_pod

        mock_node = MagicMock()
        mock_node.spec.provider_id = "aws:///us-west-2a/i-1234567890abcdef0"
        mock_core_api.return_value.read_node.return_value = mock_node

        result = app.get_affected_node_from_pod(
            "test-cluster", ["test-pod"], "default", None, "role-arn"
        )

        assert result == ["i-1234567890abcdef0"]


class TestAffectedResourceInCluster:
    """Test affected resource detection in cluster"""

    @patch.object(app, "get_affected_pods")
    def test_get_affected_resource_service_account(self, mock_get_pods):
        """Test service account resource detection"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Details": {
                                    "Other": {
                                        "kubernetesDetails/kubernetesUserDetails/username": "system:serviceaccount:namespace:service-account"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }
        mock_get_pods.return_value = ["pod1", "pod2"]

        resource_type, namespace, pods = app.get_affected_resource_in_cluster(
            event, "test-cluster", None, "role-arn"
        )

        assert resource_type == "ServiceAccount"
        assert namespace == "namespace"
        assert pods == ["pod1", "pod2"]

    def test_get_affected_resource_node(self):
        """Test node resource detection"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Details": {
                                    "Other": {
                                        "kubernetesDetails/kubernetesUserDetails/username": "system:node:ip-10-0-1-100.us-west-2.compute.internal"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }

        resource_type, namespace, pods = app.get_affected_resource_in_cluster(
            event, "test-cluster", None, "role-arn"
        )

        assert resource_type == "Node"
        assert namespace == "none"
        assert pods == []

    @patch.object(app, "get_affected_pods")
    def test_get_affected_resource_deployment(self, mock_get_pods):
        """Test deployment resource detection"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Details": {
                                    "Other": {
                                        "kubernetesDetails/kubernetesUserDetails/username": "user",
                                        "kubernetesDetails/kubernetesWorkloadDetails/type": "deployments",
                                        "kubernetesDetails/kubernetesWorkloadDetails/name": "test-deployment",
                                        "kubernetesDetails/kubernetesWorkloadDetails/namespace": "default",
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }
        mock_get_pods.return_value = ["pod1"]

        resource_type, namespace, pods = app.get_affected_resource_in_cluster(
            event, "test-cluster", None, "role-arn"
        )

        assert resource_type == "Deployment"
        assert namespace == "default"
        assert pods == ["pod1"]

    @patch.object(app, "get_affected_pods")
    def test_get_affected_resource_pods(self, mock_get_pods):
        """Test pods resource detection"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Details": {
                                    "Other": {
                                        "kubernetesDetails/kubernetesUserDetails/username": "user",
                                        "kubernetesDetails/kubernetesWorkloadDetails/type": "pods",
                                        "kubernetesDetails/kubernetesWorkloadDetails/name": "pod1 pod2",
                                        "kubernetesDetails/kubernetesWorkloadDetails/namespace": "default",
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }

        mock_get_pods.return_value = ["should not be called for pods"]

        resource_type, namespace, pods = app.get_affected_resource_in_cluster(
            event,
            "test-cluster",
            None,
            "arn:aws:iam::123456789012:role/test-role",
        )

        # A pods finding is a pods finding. This asserted "Deployment" because
        # `if x == "deployments" or "deployment":` is always true, so the Pods
        # branch was unreachable and the pod names were looked up as a deployment
        # name - which matches nothing. The names come straight off the finding,
        # space separated, so get_affected_pods is not consulted at all.
        assert resource_type == "Pods"
        assert namespace == "default"
        assert pods == ["pod1", "pod2"]
        mock_get_pods.assert_not_called()

    @patch.object(app, "get_affected_pods")
    def test_get_affected_resource_none(self, mock_get_pods):
        """Test no supported resource type"""
        event = {
            "detail": {
                "findings": [
                    {
                        "Resources": [
                            {
                                "Details": {
                                    "Other": {
                                        "kubernetesDetails/kubernetesUserDetails/username": "user",
                                        "kubernetesDetails/kubernetesWorkloadDetails/type": "unsupported",
                                        "kubernetesDetails/kubernetesWorkloadDetails/name": "test-resource",
                                        "kubernetesDetails/kubernetesWorkloadDetails/namespace": "default",
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }

        # Mock the get_affected_pods call
        mock_get_pods.return_value = []

        resource_type, namespace, pods = app.get_affected_resource_in_cluster(
            event,
            "test-cluster",
            None,
            "arn:aws:iam::123456789012:role/test-role",
        )

        # An unrecognised workload type triggers no rollout. This asserted
        # "Deployment" because the always-true condition made the else branch
        # below unreachable, so an unsupported type was silently treated as a
        # deployment named after it.
        assert resource_type == "none"
        assert namespace == "none"
        assert pods == []
