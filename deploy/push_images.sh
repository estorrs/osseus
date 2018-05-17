# login
$(aws ecr get-login --no-include-email --region us-east-1)

# build
echo building osseus
docker build -f app/Dockerfile -t osseus app/

#tag
TAG=$(git log --format="%H" -n 1)
echo tagging osseus with commit $TAG
docker tag osseus:latest 925617864758.dkr.ecr.us-east-1.amazonaws.com/osseus:$TAG

# push
echo pushing osseus:$TAG
docker push 925617864758.dkr.ecr.us-east-1.amazonaws.com/osseus:$TAG
