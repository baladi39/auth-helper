#!/bin/bash

# Docker build and run script for AuthHelper

set -e

# Configuration
IMAGE_NAME="authhelper"
TAG="latest"
CONTAINER_NAME="authhelper-app"
PORT="8080"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building Docker image...${NC}"
docker build -t ${IMAGE_NAME}:${TAG} .

echo -e "${GREEN}Build completed successfully!${NC}"

echo -e "${YELLOW}Stopping existing container if running...${NC}"
docker stop ${CONTAINER_NAME} 2>/dev/null || true
docker rm ${CONTAINER_NAME} 2>/dev/null || true

echo -e "${YELLOW}Starting new container...${NC}"
docker run -d \
  --name ${CONTAINER_NAME} \
  -p ${PORT}:8080 \
  --restart unless-stopped \
  ${IMAGE_NAME}:${TAG}

echo -e "${GREEN}Container started successfully!${NC}"
echo -e "Application is running at: ${GREEN}http://localhost:${PORT}${NC}"
echo -e "Health check: ${GREEN}http://localhost:${PORT}/health${NC}"
echo -e "API Documentation: ${GREEN}http://localhost:${PORT}/swagger${NC}"

echo -e "\n${YELLOW}Useful commands:${NC}"
echo -e "View logs: ${GREEN}docker logs -f ${CONTAINER_NAME}${NC}"
echo -e "Stop container: ${GREEN}docker stop ${CONTAINER_NAME}${NC}"
echo -e "Remove container: ${GREEN}docker rm ${CONTAINER_NAME}${NC}"