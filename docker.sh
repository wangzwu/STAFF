#!/bin/bash

if [ -z "$1" ]
    then
        echo "No argument supplied. Type \"build\", \"run\", \"attach\" or \"rm\"."
        exit 1
fi

case $1 in
    build)
        docker build --tag staff .;
        ;;

    build_postgres)
        docker build --tag staff_postgres .;
        ;;

    run)
    	docker run -dit --privileged --cpuset-cpus $3 --memory="15g" --network host --name $2 -v /dev:/dev -v $(pwd):/STAFF staff;
        ;;

    run_bridge)
    	docker run -dit --privileged --cpuset-cpus $3 --memory="15g" --network bridge --name $2 -v /dev:/dev -v $(pwd):/STAFF staff;
        ;;

    run_exp)
    	docker run -dit --privileged --cpuset-cpus=$3 --memory="15g" --network bridge --name $2 -v /dev:/dev -v $(pwd):/STAFF --mount type=tmpfs,destination=/dev/shm staff /bin/bash -c "$(cat command)";
        ;;

    run_postgres)
    	docker run -dit --privileged --cpuset-cpus $3 --memory="15g" --network bridge -p 6666:6666 --name $2 -v /dev:/dev -v $(pwd):/STAFF staff_postgres;
        ;;

    attach)
        docker attach $2 --detach-keys ctrl-a;
        ;;

    rm)
        docker rm --force {$2};
        ;;

    rmi)
        docker rmi --force staff;
        ;;
esac
