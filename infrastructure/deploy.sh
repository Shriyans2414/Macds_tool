#!/bin/bash
set -e

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION="ap-south-1"
ECR_REPO="macds-control-plane"
IMAGE_TAG=$(git rev-parse --short HEAD)

docker build -t $ECR_REPO:$IMAGE_TAG ./control_plane
aws ecr get-login-password --region $AWS_REGION | \
    docker login --username AWS --password-stdin \
    $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
docker tag $ECR_REPO:$IMAGE_TAG \
    $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO:$IMAGE_TAG
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO:$IMAGE_TAG

aws cloudformation deploy \
    --template-file infrastructure/cloudformation.yml \
    --stack-name macds-production \
    --parameter-overrides \
        ImageTag=$IMAGE_TAG \
        MacdsApiKey=$MACDS_API_KEY \
    --capabilities CAPABILITY_IAM \
    --region $AWS_REGION

echo "Deployment complete."
aws cloudformation describe-stacks \
    --stack-name macds-production \
    --query "Stacks[0].Outputs" \
    --output table
