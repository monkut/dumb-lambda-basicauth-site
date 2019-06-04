import os
import sys
import re
import logging
from urllib.parse import unquote
from typing import Tuple, Union, List
from base64 import b64decode


SALT = os.getenv('SALT', 'kkdkjoias89299292')
BASIC_AUTH_USERNAME = os.getenv('BASIC_AUTH_USERNAME', None)
BASIC_AUTH_PASSWORD = os.getenv('BASIC_AUTH_PASSWORD', None)

if not BASIC_AUTH_USERNAME or not BASIC_AUTH_PASSWORD:
    raise ValueError(f'Required ENVAR not given (BASIC_AUTH_USERNAME|BASIC_AUTH_PASSWORD): {BASIC_AUTH_USERNAME}:{BASIC_AUTH_PASSWORD}')

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(name)s) %(funcName)s: %(message)s'
)

logger = logging.getLogger()

LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
if LOG_LEVEL and LOG_LEVEL in ('INFO', 'ERROR', 'WARNING', 'DEBUG', 'CRITICAL'):
    level = getattr(logging, LOG_LEVEL)
    logger.setLevel(level)


class DecodeError(Exception):
    pass


class HttpVerb:
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    PATCH   = "PATCH"
    HEAD    = "HEAD"
    DELETE  = "DELETE"
    OPTIONS = "OPTIONS"
    ALL     = "*"


class AuthPolicy:
    """From awslabs blueprint https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/python/api-gateway-authorizer-python.py"""
    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ""

    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ""

    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = "2012-10-17"

    # The regular expression used to validate resource paths for the policy
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"

    # these are the internal lists of allowed and denied methods. These are lists
    # of objects and each object has 2 properties: A resource ARN and a nullable
    # conditions statement.
    # the build method processes these lists and generates the approriate
    # statements for the final policy
    allowMethods = []
    denyMethods = []

    # The API Gateway API id. By default this is set to '*'
    restApiId = "*"

    # The region where the API is deployed. By default this is set to '*'
    region = "*"

    # The name of the stage used in the policy. By default this is set to '*'
    stage = "*"

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource.endswith("/"):
            resource = resource[1:]  # remove trailing slash, '/'

        resourceArn = f"arn:aws:execute-api:{self.region}:{self.awsAccountId}:{self.restApiId}/{self.stage}/{verb}/{resource}"
        logger.info(f'resourceArn: {resourceArn}')

        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            statements.append(statement)

        return statements

    def allowAllMethods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId' : self.principalId,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Deny", self.denyMethods))

        return policy


def parse_arn(arn_str: str) -> Tuple[str, str, str, Union[str, None], str, Union[List[str], None]]:
    """
    https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
    arn:partition:service:region:account-id:resource
    arn:partition:service:region:account-id:resourcetype/resource
    arn:partition:service:region:account-id:resourcetype/resource/qualifier
    arn:partition:service:region:account-id:resourcetype/resource:qualifier
    arn:partition:service:region:account-id:resourcetype:resource
    arn:partition:service:region:account-id:resourcetype:resource:qualifier

    :return: service, region, account_id, resource_type, resource, qualifier
    """
    *_, service, region, account_id, resource_elements = arn_str.split(':', 5)

    resource_type = None
    resource = None
    qualifiers = None
    if not any(separator in resource_elements for separator in (':', '/')):
        resource = resource_elements
    elif ':' in resource_elements and '/' not in resource_elements:
        if resource_elements.count(':') == 1:
            resoruce_type, resource = resource_elements.split(':')
        elif resource_elements.count(':') >= 2:
            resource_type, resource, *qualifiers = resource_elements.split(':')
    elif ':' not in resource_elements and '/' in resource_elements:
        if resource_elements.count('/') == 1:
            resoruce_type, resource = resource_elements.split('/')
        elif resource_elements.count('/') >= 2:
            resource_type, resource, *qualifiers = resource_elements.split('/')
    elif ':' in resource_elements and '/' in resource_elements:
        # 'arn:partition:service:region:account-id:resourcetype/resource:qualifier'
        resource_type, remaining = resource_elements.split('/')
        resource, qualifier = remaining.split(':')

    return service, region, account_id, resource_type, resource, qualifiers


def basicauth_decode(encoded_str: str) -> Tuple[str, str]:
    """
    Decode an encrypted HTTP basic authentication string. Returns a tuple of
    the form (username, password), and raises a DecodeError exception if
    nothing could be decoded.
    """
    split = encoded_str.strip().split(' ')

    # If split is only one element, try to decode the username and password
    # directly.
    if len(split) == 1:
        try:
            username, password = b64decode(split[0]).decode().split(':', 1)
        except:
            raise DecodeError

    # If there are only two elements, check the first and ensure it says
    # 'basic' so that we know we're about to decode the right thing. If not,
    # bail out.
    elif len(split) == 2:
        if split[0].strip().lower() == 'basic':
            try:
                username, password = b64decode(split[1]).decode().split(':', 1)
            except:
                raise DecodeError
        else:
            raise DecodeError

    # If there are more than 2 elements, something crazy must be happening.
    # Bail.
    else:
        raise DecodeError

    return unquote(username), unquote(password)


def check_basicauth_header_authorization_handler(event, context):
    """Confirm that the request has the expected BasicAuthorization Header"""
    authorization_header = event['headers'].get('Authorization', None)
    username = None
    password = None
    if not authorization_header:
        logger.warning(f'Authorization Header not given!')
        logger.warning(f'headers: {event["headers"]}')
        raise Exception('Unauthorized - authorization_header')  # Raises 401 response from API Gateway
    else:
        try:
            username, password = basicauth_decode(authorization_header)
        except DecodeError as e:
            # return 400 error
            logger.error(f'DecodeError: {e.args}')
            raise Exception(f'Unauthorized - DecodeError: {e.args}')  # Raises 401 response from API Gateway
        # prepare reference principal_id
        # https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-bucket-user-policy-specifying-principal-intro.html
        principal_id = '*'

    if username != BASIC_AUTH_USERNAME:
        raise Exception('Unauthorized - BASIC_AUTH_USERNAME')  # Raises 401 response from API Gateway
    elif password != BASIC_AUTH_PASSWORD:
        raise Exception('Unauthorized - BASIC_AUTH_PASSWORD')  # Raises 401 response from API Gateway

    # arn:partition:service:region:account-id:resourcetype/resource/qualifier
    # arn:aws:execute-api:region:account-id:api-id/stage-name/HTTP-VERB/resource-path
    # api-id = resource_type
    # stage-name = resource
    method_arn = event['methodArn']
    logger.info(f'Parsing methodArn({event["methodArn"]}) ...')
    service, region, account_id, resource_type, resource, qualifiers = parse_arn(method_arn)

    policy = AuthPolicy(principal_id, account_id)
    policy.restApiId = resource_type
    policy.stage = resource
    policy.allowAllMethods()

    authorization_response = policy.build()
    # add additional key-value pairs associated with the authenticated principal these are made available by APIGW like so: $context.authorizer.<key>
    # additional context is cached
    # context = {'key': 'value', ...  }
    return authorization_response
