#!/usr/bin/env python3
import os
import aws_cdk as cdk
from aws_cdk_valohai.valohai_stack import ValohaiSelfHostedStack


app = cdk.App()

valohai_self_hosted_stack = ValohaiSelfHostedStack(app, "ValohaiSelfHostedIAMStack", env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION')))

tags = valohai_self_hosted_stack.node.try_get_context("tags")
for key, value in tags.items():
    cdk.Tags.of(valohai_self_hosted_stack).add(key, value)

app.synth()
