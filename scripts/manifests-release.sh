#! /usr/bin/env bash
set -euox pipefail

SRCROOT="$( CDPATH='' cd -- "$(dirname "$0")/.." && pwd -P )"
AUTOGENMSG="# This is an auto-generated file. DO NOT EDIT"

KUSTOMIZE="${1:-}"
if [ -z "$KUSTOMIZE" ]; then
    echo "Path to kustomize not provided"
    exit 1
fi

IMAGE_TAG="${2:-}"
if [ -z "$IMAGE_TAG" ]; then
    echo "Image tag not provided"
    exit 1
fi

IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-quay.io/argoprojlabs/argocd-ephemeral-access}"
IMAGE_FQN="$IMAGE_NAMESPACE:$IMAGE_TAG"

$KUSTOMIZE version
cd ${SRCROOT}/config/default && $KUSTOMIZE edit set image argoproj-labs/argocd-ephemeral-access=${IMAGE_FQN}
echo "${AUTOGENMSG}" > "${SRCROOT}/install.yaml"
$KUSTOMIZE build "${SRCROOT}/config/default" >> "${SRCROOT}/install.yaml"
