#!/bin/bash
APP_NAME="public-key-value-store-server"
sudo docker rm -f $APP_NAME || echo ""
#sudo docker run -it $APP_NAME
id=$(sudo docker run -dit \
--name $APP_NAME \
--restart='always' \
-v $(pwd)/SAVE_FILES:/home/morphs/SAVE_FILES:rw \
--mount type=bind,source="$(pwd)"/config.json,target=/home/morphs/KeyValueStoreServer/config.json \
-p 7393:7393 \
$APP_NAME config.json)
sudo docker logs -f $id
