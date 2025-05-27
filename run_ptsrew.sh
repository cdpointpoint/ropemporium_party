mkdir -p share
docker run -it --rm  -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix   \
  --name pts_rew -v $(pwd)/share:/share cdpointpoint/ropemporium:0.1 /bin/bash
# --user $(id -u):$(id -u) \
