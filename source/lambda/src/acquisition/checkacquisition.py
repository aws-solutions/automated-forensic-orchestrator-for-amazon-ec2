from ..common.common import create_response
from ..common.log import get_logger
from ..common.redact import redact

logger = get_logger(__name__)


def lambda_handler(event, context):
    logger.info("Got event %s", redact(event))
    input_body = {}
    input_body = event["Payload"]["body"]
    output = input_body.copy()
    if "clusterInfo" in input_body:
        instance_acquisition = input_body["isAcquisitionRequired"]
        affected_node_instances = input_body["clusterInfo"]["affectedNode"]
        filtered_instances = []
        # Loop through each instance ID in the list
        for instance_id in affected_node_instances:
            # Check if the instance ID exists in the dictionary and its value is True
            if (
                instance_id in instance_acquisition
                and instance_acquisition[instance_id]
            ):
                filtered_instances.append(instance_id)
        if len(filtered_instances) > 0:
            output["isAcquisitionRequired"] = True
            output["clusterInfo"]["affectedNode"] = filtered_instances
        else:
            output["isAcquisitionRequired"] = False
    return create_response(200, output)
