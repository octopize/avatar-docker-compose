# Docker deployment

## Objective

The goal of this file folder is to have a pre-packaged directory to easily deploy a production-grade Avatars deployment using `docker`.

## Prerequisite

- Install `git`

## Download

Once you are on the target server where you want to install the stack, run the following commands to only
download the necessary docker folder.

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/octopize/avatar-deployment
cd avatar-deployment
git sparse-checkout set docker
```
