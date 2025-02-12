# How to create a custom Ubuntu image

In the context of adding more utilities to the Ubuntu cloud image being used
for integration testing, this quick guide details how to achieve the proper
modification of an official Ubuntu cloud image.

## Image generation script

This [script](../scripts/build-custom-image.sh) can be used to generate a custom image (needs to be modified per architecture/distribution image)

## Switch CI to use the new image

### Upload to Azure storage

A command like the following can be used to upload the image:

`az storage blob upload --account-name cloudhypervisorstorages --container-name '$web' --name jammy-server-cloudimg-amd64-custom-20241017-0.qcow2 --file jammy-server-cloudimg-amd64-custom-20241017-0.qcow2 --sas-token <redacted>`

### Update integration tests

Last step is about updating the integration tests to work with this new image.
The key point is to identify where the Linux filesystem partition is located,
as we might need to update the direct kernel boot command line, replacing
`/dev/vda1` with the appropriate partition number.

Update all references to the previous image name to the new one.

## NVIDIA image for VFIO bare-metal CI

Uncomment "VFIO_CUSTOM_IMAGE" in the script listed above to generate the custom image used for the VFIO worker.