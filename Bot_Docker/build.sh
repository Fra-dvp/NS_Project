
for num in 1 2 3 4 5 6 7 8 9 10
do
echo "Build docker image number "
echo "${num}"

s_DOCKER_IMAGE_NAME = "ubuntu_telnet ${num}"

sudo docker build -t --cap-add=NET_ADMIN $(s_DOCKER_IMAGE_NAME) .

done