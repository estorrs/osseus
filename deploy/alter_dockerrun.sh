TAG=$(git log --format="%H" -n 1)
sed -i "s/osseus:.*\",/osseus:$TAG\",/" Dockerrun.aws.json

