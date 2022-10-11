import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_cdk_valohai.aws_cdk_valohai_stack import AwsCdkValohaiStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_cdk_valohai/aws_cdk_valohai_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsCdkValohaiStack(app, "aws-cdk-valohai")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
