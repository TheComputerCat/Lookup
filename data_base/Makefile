start:
	docker start postgresDataBase
run:
	docker run --rm -d -p 5432:5432  \
	-v myVol:/var/lib/postgresql/data \
	-e POSTGRES_USER=postgresusr \
	-e POSTGRES_PASSWORD=complex_password \
	--name postgresDataBase postgres \
	-c listen_addresses='*'
end:
	docker stop postgresDataBase