#!/bin/bash
aws secretsmanager create-secret \
    --name macds/api-key \
    --secret-string "$(openssl rand -hex 32)" \
    --region ap-south-1
