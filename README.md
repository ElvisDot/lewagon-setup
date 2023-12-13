# lewagon-setup
The unoffical LeWagon setup doctor. A script that shows and fixes setup issues.

## Web

<details>

    curl -s https://raw.githubusercontent.com/ElvisDot/lewagon-setup/master/doc.sh | bash -s -- --course web

If it says ``curl: command not found`` try this

    wget -q -O - https://raw.githubusercontent.com/ElvisDot/lewagon-setup/master/doc.sh | bash -s -- --course web

</details>

## Data

<details>

    curl -s https://raw.githubusercontent.com/ElvisDot/lewagon-setup/master/doc.sh | bash -s -- --course data

If it says ``curl: command not found`` try this

    wget -q -O - https://raw.githubusercontent.com/ElvisDot/lewagon-setup/master/doc.sh | bash -s -- --course data

</details>

## Your system is so broken it does not let you run the doctor?

<details>

If running the doctor gives you ``curl: (6) Could not resolve host: raw.githubusercontent.com`` try this

    echo '185.199.108.133    raw.githubusercontent.com # doc.sh' | sudo tee -a /etc/hosts

Then run the doctor. And afterwards cleanup with this command

    grep -v 'doc.sh' /etc/hosts > /tmp/hosts && sudo mv /tmp/hosts /etc/hosts

</details>
