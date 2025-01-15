from os import path
from aws_cdk import (
    Stack,
    aws_lambda as lambda_,
    aws_apigateway as apigateway,
    aws_iam as iam,
    Duration,
    BundlingOptions
)
from constructs import Construct


class CdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        lambda_role = iam.Role(self, 'FetchCredentialsLambdaRole',
                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        lambda_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaBasicExecutionRole"))
        lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                's3:ListAccessGrants',
                'identitystore:GetUserId',
                'sso-oauth:CreateTokenWithIAM',
                'sts:AssumeRole',
                'sts:SetContext'
            ],
            resources=['*'],
        ))
        fn_fetch_credentials = lambda_.Function(self, "FetchCredentialsLambda",
                                                runtime=lambda_.Runtime.PYTHON_3_12,
                                                handler="index.handler",
                                                code=lambda_.Code.from_asset("./lambda",
                                                                             bundling=BundlingOptions(
                                                                                 image=lambda_.Runtime.PYTHON_3_12.bundling_image,
                                                                                 command=[
                                                                                     'bash', '-c',
                                                                                     'pip install --platform manylinux2014_x86_64 --only-binary=:all: -r requirements.txt -t /asset-output && cp -au . /asset-output'
                                                                                 ],
                                                                             ), ),
                                                role=lambda_role,
                                                timeout=Duration.seconds(30),
                                                environment={
                                                    'LOG_LEVEL': 'DEBUG'
                                                }
                                                )
        api = apigateway.LambdaRestApi(
            self,
            "CredentialsAPI",
            handler=fn_fetch_credentials,
            proxy=False,
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS
            )
        )
        fetch_credentials_resource = api.root.add_resource("FetchCredentials")
        fetch_credentials_resource.add_method('GET')
