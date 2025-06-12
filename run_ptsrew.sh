#! /bin/sh
# run the workshop docker image
docker run -it --rm  -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix   \
  --name pts_rew -v $(pwd)/challenges:/share cdpointpoint/ropemporium:0.2 /usr/bin/tmux
# --user $(id -u):$(id -u) \
