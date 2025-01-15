import json
import jwt
import boto3
import logging
import os
from botocore.exceptions import ClientError
idc_client = boto3.client('identitystore')
s3_control = boto3.client('s3control')
oidc_client = boto3.client('sso-oidc')
sts_client = boto3.client('sts')
LOG_FORMAT = '{"time_stamp": "%(asctime)s", "log_level": "%(levelname)s", "log_message": %(message)s}'
logging.basicConfig(format=LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', 'INFO')))
region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
ACCESS_DENIED_RESPONSE: dict = {
    "statusCode": 403,
    "headers": {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    },
    "body": json.dumps({"response": 'Missing Authorization'})
}
AUDIENCE = '2b7c4fc8-2f89-45e1-b537-06de31fd03c5'
IDENTITY_STORE_ID = 'd-9067f58a64'
JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
IDC_CUSTOMER_APP_ARN = 'arn:aws:sso::099115825276:application/ssoins-7223137f0c446cfa/apl-8f93bfe6823d9098'
TRANSIENT_ROLE_ARN = 'arn:aws:iam::099115825276:role/S3AccessGrantsWebApp-UserTransientRole6BA15CA0-QoQLRrgedhIf'
JWKS_URL = 'https://login.microsoftonline.com/e0916847-79ae-4d02-9184-ba50443a043d/discovery/v2.0/keys'
# For Okta is sub, for Azure Entra ID is preferred_username
USERNAME_ATTRIBUTE = 'preferred_username'


class InvalidGrantException(Exception):
    pass


def fetch_credentials(event, token):
    end_user_credentials = {
        'AccessKey': 'null',
        'SecretKey': 'null',
        'SessionToken': 'null',
        'Expiration': 'null',
    }

    try:
        logger.debug('Getting IdC token with CreateTokenWithIAM')
        url = oidc_client.create_token_with_iam(
            clientId=IDC_CUSTOMER_APP_ARN,
            grantType=JWT_BEARER_GRANT_TYPE,
            assertion=token
        )
        logger.debug(f'SSO-OIDC response: {url}')
        # This token is a response from our call to Identity Center. I assume it is safe to not validate the signature
        sts_identity_context = jwt.decode(url['idToken'], options={"verify_signature": False})['sts:identity_context']
        sts_credentials = sts_client.assume_role(
            RoleArn=TRANSIENT_ROLE_ARN,
            RoleSessionName=f'transient-s3ag-{IDENTITY_STORE_ID}',
            ProvidedContexts=[
                {
                    'ProviderArn': 'arn:aws:iam:aws::contextProvider/IdentityCenter',
                    'ContextAssertion': sts_identity_context
                }
            ]
        )
        logger.info('Getting transient role with STS:AssumeRole')
        logger.debug(json.dumps(sts_credentials, default=str))
        transient_credentials = sts_credentials['Credentials']
        return {
            'Credentials': {
                'AccessKeyId': transient_credentials['AccessKeyId'],
                'SecretKey': transient_credentials['SecretAccessKey'],
                'SessionToken': transient_credentials['SessionToken'],
                'Expiration': transient_credentials['Expiration']
            },
        }
    except ClientError as e:
        logger.exception(e)
        if e.response['Error']['Code'] == 'InvalidGrantException':
            raise InvalidGrantException(e)
    except Exception as e:
        logger.exception(e)
        raise


def handler(event, context):
    logger.debug(boto3.__version__)
    logger.debug(json.dumps(event, indent=2))
    if not event.get('headers', {}).get('Authorization'):
        logger.info('Missing Authorization')
        return ACCESS_DENIED_RESPONSE
    try:
        # Validating JWT token before proceeding (https://pyjwt.readthedocs.io/en/stable/usage.html)
        # URL with the public keys
        jwks_url = 'https://login.microsoftonline.com/common/discovery/keys'
        jwks_client = jwt.PyJWKClient(jwks_url)
        token = event.get('headers', {}).get('Authorization', '')
        # AUD from token
        aud = AUDIENCE
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(token,
                             signing_key.key,
                             algorithms=['RS256'],
                             options={"require": ["exp", "iss", "sub", "aud"]},
                             audience=aud, )

        logger.debug(payload)
        if event['resource'] == '/FetchCredentials':
            logger.info('Invoking fetch_credentials function')
            response = fetch_credentials(event, token)
        else:
            logger.info('Invalid API resource!')
            return ACCESS_DENIED_RESPONSE

    except jwt.ExpiredSignatureError:
        logger.exception('Invalid JWT')
        return ACCESS_DENIED_RESPONSE
    except InvalidGrantException:
        return {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({"response": 'Invalid token exception'})
        }
    except Exception as err:
        logger.exception(err, exc_info=True)
        return ACCESS_DENIED_RESPONSE

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({'response': response}, default=str)
    }
