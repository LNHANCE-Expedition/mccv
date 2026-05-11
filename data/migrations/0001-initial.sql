create table mccv_secret (
	master_xpriv text,
	descriptor text,
	change_descriptor text
);

create table mccv_vault (
	id integer primary key,
	name text,
	scale integer,
	"max" integer,
	cold_xpub text,
	hot_xpub text,
	delay_per_increment integer,
	max_withdrawal_per_step integer,
	max_deposit_per_step integer,
	max_depth integer
);

create table mccv_transaction (
	vault integer,
	txid blob,
	primary key (vault, txid),
	constraint valid_vault_id
		foreign key (vault) references mccv_vault (id),
	constraint valid_txid
		foreign key (txid) references "transaction" (txid)
) strict, without rowid;

create table block (
	block_hash blob not null,
	parent_block_hash blob,
	height integer not null,
	primary key (block_hash),
	constraint valid_parent_block_hash
		foreign key (parent_block_hash) references block (block_hash)
) strict, without rowid;

create view chain_tip (
	block_hash,
	height
) as select
	block.block_hash,
	block.height
from block
where not exists (
	select 1
		from block as child_block
		where block.block_hash = child_block.parent_block_hash
);

CREATE INDEX block_by_parent ON block(parent_block_hash);

create unique index unique_genesis_block
	on block((1))
	where block_hash is null;

create view chain (
	chain_tip_hash,
	block_hash,
	height
) as with recursive c (
	chain_tip_hash,
	parent_block_hash,
	block_hash,
	height
) as not materialized (
	select
		tip.block_hash as chain_tip_hash,
		block.parent_block_hash as parent_block_hash,
		tip.block_hash as block_hash,
		tip.height as height
	from
		chain_tip tip
	join block
		on block.block_hash = tip.block_hash

	union all

	select
		c.chain_tip_hash as chain_tip_hash,
		parent.parent_block_hash as parent_block_hash,
		parent.block_hash as block_hash,
		parent.height as height
	from
		c
	join block parent on
		c.parent_block_hash = parent.block_hash
) select
	chain_tip_hash,
	block_hash,
	height
from c;

create table "transaction" (
	txid blob not null,
	"transaction" blob not null,
	primary key (txid)
) strict, without rowid;

create table transaction_confirmation (
	txid blob,
	block_hash blob,
	primary key (txid, block_hash),
	foreign key (txid) references "transaction" (txid),
	foreign key (block_hash) references block (block_hash)
) strict, without rowid;
