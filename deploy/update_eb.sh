TAG=$(git log --format="%H" -n 1)
eb deploy --label $TAG
