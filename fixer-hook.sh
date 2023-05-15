#!/usr/bin/env bash
ptb_service_user=$(cat "$HOME"/.config/ptb-service-user)
LATEST_TAG=$(git ls-remote --tags "https://github.com/$GITHUB_USER/$REPO_NAME.git" | awk '{print $2}' | grep -v '{}' | sort -V | tail -n1 | sed 's|refs/tags/||')

# Set Github repository details
GITHUB_USER="BlurryFlurry"
REPO_NAME="tg-vps-manager"
LOCAL_REPO_DIR="/home/$ptb_service_user/bot"
# Go to the local directory
cd "$LOCAL_REPO_DIR" || exit

touch "$HOME"/.config/ptb-service-version.txt

sudo -u $ptb_service_user git reset --hard origin/main && git clean -f -d
sudo -u $ptb_service_user git checkout main -f
sudo -u $ptb_service_user git reset --hard origin/main && git clean -f -d
sudo -u $ptb_service_user git pull --tags "https://github.com/$GITHUB_USER/$REPO_NAME.git" "$LATEST_TAG"
chown $ptb_service_user:$ptb_service_user -R .
