#!/usr/bin/env bash
set -xv
ptb_service_user=$(cat "$HOME"/.config/ptb-service-user)
release=$2
if [ -z "$2" ]
  then
    release=$(cat /home/"$ptb_service_user"/bot/release-id.txt)
fi

# Set Github repository details
GITHUB_USER="BlurryFlurry"

REPO_NAME="tg-vps-manager"
LOCAL_REPO_DIR="/home/$ptb_service_user/bot"
# Go to the local directory
cd "$LOCAL_REPO_DIR" || exit
LATEST_TAG=$(git ls-remote --tags "https://github.com/$GITHUB_USER/$REPO_NAME.git" | awk '{print $2}' | grep -v '{}' | sort -V | tail -n1 | sed 's|refs/tags/||')

touch "$HOME"/.config/ptb-service-version.txt

sudo -u $ptb_service_user git config --global --add safe.directory "$LOCAL_REPO_DIR"
sudo -u $ptb_service_user git reset --hard origin/main && git clean -f -d
sudo -u $ptb_service_user git checkout main -f
sudo -u $ptb_service_user git reset --hard origin/main && git clean -f -d
sudo -u $ptb_service_user git pull --tags "https://github.com/$GITHUB_USER/$REPO_NAME.git" "$LATEST_TAG"
chown $ptb_service_user:$ptb_service_user -R .

# install vnstat if release ID is greater than 26
if [ "$release" -gt 26 ]
then
    echo "Installing vnstat"
    sudo apt-get install -y vnstat
    sudo systemctl enable vnstat
    sudo systemctl start vnstat
    echo "vnstat installed"
fi