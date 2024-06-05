#!/bin/bash

# Create User Pool
USER_POOL_ID=$(
  aws cognito-idp create-user-pool \
    --pool-name ${COGNITO_USER_POOL} \
    --query UserPool.Id \
    --output text \
    --endpoint-url ${AWS_URL} \
    --username-attributes email \
    --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":false}}' \
)

if [ -z "$USER_POOL_ID" ]; then
  echo "Error creating user pool"
  exit 1
fi

CLIENT_ID=$(
  aws cognito-idp create-user-pool-client \
    --client-name ${COGNITO_CLIENT_NAME} \
    --user-pool-id ${USER_POOL_ID} \
    --query UserPoolClient.ClientId \
    --output text \
    --endpoint-url ${AWS_URL} \
)

if [ -z "$CLIENT_ID" ]; then
  echo "Error creating user pool client"
  exit 1
fi

aws cognito-idp admin-create-user \
  --user-pool-id ${USER_POOL_ID} \
  --username ${COGNITO_USER_NAME} \
  --user-attributes Name=email,Value=${USER_EMAIL} Name=email_verified,Value=true \
  --message-action SUPPRESS \
  --endpoint-url ${AWS_URL} \

aws cognito-idp admin-set-user-password \
  --user-pool-id ${USER_POOL_ID} \
  --username ${COGNITO_USER_NAME} \
  --password ${COGNITO_USER_PASSWORD} \
  --permanent \
  --endpoint-url ${AWS_URL}

aws cognito-idp list-users \
  --user-pool-id ${USER_POOL_ID} \
  --endpoint-url ${AWS_URL}

echo "User pool ID: $USER_POOL_ID"
echo "Client ID: $CLIENT_ID"

aws cognito-idp admin-initiate-auth \
  --user-pool-id ${USER_POOL_ID} \
  --client-id ${CLIENT_ID} \
  --auth-flow ADMIN_NO_SRP_AUTH \
  --auth-parameters "USERNAME=${COGNITO_USER_NAME},PASSWORD=${COGNITO_USER_PASSWORD}" \
  --endpoint-url ${AWS_URL}

echo "Cognito Script completed."
