create table mccv_secret (
	id integer primary key,
	master_fingerprint blob not null,
	master_xpriv text,
	hot_path text not null,
	hot_xpriv text not null,
	descriptor text not null,
	change_descriptor text not null,
	foreign key ( id ) references mccv_vault ( id )
);

create table mccv_rpc_config (
	id integer primary key,

	rpc_url text,
	rpc_username text,
	rpc_password text,
	rpc_cookie text,

	constraint rpc_user_auth
	check (
		case
		-- Corresponds to bitcoincore_rpc::Auth::None
		when rpc_cookie is null and rpc_username is null and rpc_password is null then 1
		-- Corresponds to bitcoincore_rpc::Auth::UserPass
		when rpc_username not null and rpc_password not null then 1
		-- Corresponds to bitcoincore_rpc::Auth::CookieFile
		when rpc_cookie not null then 1
		else 0
		end
	),

	foreign key ( id ) references mccv_vault ( id )
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
	max_depth integer,
	constraint unique_name
		unique ( name )
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
	primary key (block_hash)
) strict, without rowid;

create table sparse_chain (
	block_hash blob not null,
	sparse_parent_block_hash blob,
	vault integer not null,

	primary key ( vault, block_hash ),
	foreign key ( vault, sparse_parent_block_hash )
		references sparse_chain ( vault, block_hash ),
	foreign key ( vault )
		references mccv_vault ( id )
) strict, without rowid;

-- FIXME: It might make sense to directly record chain tips
-- With the posibility that two contracts might share a database
-- but one might not be synced as high as the other, I think there's some benefit
-- to manually maintaining that.
create view chain_tip (
	block_hash,
	height,
	vault
) as select
	sparse_chain.block_hash as block_hash,
	block.height as height,
	sparse_chain.vault as vault
from sparse_chain
join block
	on block.block_hash = sparse_chain.block_hash
where not exists (
	select 1
		from sparse_chain as child_block
		where child_block.sparse_parent_block_hash = sparse_chain.block_hash
			and child_block.vault = sparse_chain.vault
)
and not exists (
	select 1
		from block as child_block
		where child_block.parent_block_hash = sparse_chain.block_hash
);

create index sparse_block_by_parent ON sparse_chain ( vault, block_hash );

create view contract_chain (
	chain_tip_hash,
	block_hash,
	parent_block_hash,
	sparse_parent_block_hash,
	height,
	vault
) as with recursive c (
	chain_tip_hash,
	block_hash,
	parent_block_hash,
	sparse_parent_block_hash,
	height,
	vault
) as not materialized (
	select
		tip.block_hash as chain_tip_hash,
		tip.block_hash as block_hash,
		block.parent_block_hash as parent_block_hash,
		sparse_chain.sparse_parent_block_hash as sparse_parent_block_hash,
		tip.height as height,
		tip.vault as vault
	from
		chain_tip tip
	join sparse_chain
		on sparse_chain.block_hash = tip.block_hash
			and sparse_chain.vault = tip.vault
	join block
		on block.block_hash = tip.block_hash

	union all

	select
		child.chain_tip_hash as chain_tip_hash,
		parent.block_hash as block_hash,
		parent.parent_block_hash as parent_block_hash,
		sparse_chain.sparse_parent_block_hash as sparse_parent_block_hash,
		parent.height as height,
		child.vault as vault
	from
		c as child
	join sparse_chain
		on sparse_chain.block_hash = child.sparse_parent_block_hash
			and sparse_chain.vault = child.vault
	join block parent
		on parent.block_hash = child.sparse_parent_block_hash
) select
	chain_tip_hash,
	block_hash,
	parent_block_hash,
	sparse_parent_block_hash,
	height,
	vault
from c
where block_hash is not null;

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
