#!/bin/bash
aws --endpoint-url=${AWS_URL} ses verify-domain-identity --domain ${SES_DOMAIN}
aws --endpoint-url=${AWS_URL} ses verify-email-identity --email-address ${USER_EMAIL}
aws --endpoint-url=${AWS_URL} ses list-identities
echo "SES Script completed."
