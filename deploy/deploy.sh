# login
$(aws ecr get-login --no-include-email --region us-east-1)

# build
echo building ab-session-webapp
docker build -t ab-session-webapp .

#tag
TAG=$(git log --format="%H" -n 1)
echo tagging ab-session-webapp with commit $TAG
docker tag ab-session-webapp:latest 779064369310.dkr.ecr.us-east-1.amazonaws.com/ab-session-webapp:$TAG

# push
echo pusing ab-session-webapp:$TAG
docker push 779064369310.dkr.ecr.us-east-1.amazonaws.com/ab-session-webapp:$TAG

# alter dockerrun
sed -i "s/ab-session-webapp:.*\",/ab-session-webapp:$TAG\",/" Dockerrun.aws.json

# deploy new webapp
eb deploy --label $TAG
