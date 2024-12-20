create table mccv_secret (
	master_xpriv text,
	descriptor text,
	change_descriptor text
);

create table mccv_vault (
	id integer primary key,
	name text
);

create table mccv_state (
	vault integer,
	depth integer,
	txid blob,
	vault_txout integer,
	withdrawal_txout integer,
	script_pubkey blob,
	height integer,
	block blob,
	primary key (vault, depth),
	foreign key (vault) references mccv_vault (id)
);
