#!/bin/bash
set -eu

#code-server --install-extension golang.go &

#code-server --install-extension ms-python.python &

sudo useradd -s $(which zsh) -m ${USER_NAME}

sudo chown -R ${USER_NAME}:${USER_NAME} /home/${USER_NAME} 

sudo echo "${USER_NAME} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${USER_NAME}

sudo chsh -s $(which zsh)

declare -a exts=("golang.go" "a-h.templ" "saoudrizwan.claude-dev" "ms-python.python")

for i in "${exts[@]}"
do
   su $USER_NAME --command "code-server --install-extension $i &"
done

su $USER_NAME --command "code-server --auth none --bind-addr 0.0.0.0:8080 '/home/${USER_NAME}'"