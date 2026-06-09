#! /bin/sh

printf "Withdrawal initiated. TXID $1\n"

while true; do
	printf "Approve? (y/N) "
	if ! read -r answer ; then
		answer=
	fi

	case "$answer" in
		[Yy]|[Yy][Ee][Ss] )
			exit 0
			break
			;;

		''|[Nn]|[Nn][Oo] )
			exit 1
			break
			;;

		* )
			printf "Please enter yes or no\n" >&2 
			break
			;;
	esac
done
