#! /bin/sh
# run the workshop docker image
# the current challege directory is mounted as /share in the docker image
# and linked with /home/pts/challenge 
docker run -it --rm  -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix   \
  --name pts_rew -v $(pwd)/challenges:/share cdpointpoint/ropemporium /usr/bin/tmux
# --user $(id -u):$(id -u) \
