
--
-- Table: AUTH_USER
--
create table AUTH_USER (
	OBJID			integer			not null,
	USER_STATUS		char(1)			not null,
	USER_EMAIL		varchar2(128)	not null,
	USER_LOGIN		varchar2(24)	not null,
	FIRST_NAME		varchar2(40)	        ,
	LAST_NAME		varchar2(80)			,
	CUSTOM_1		varchar2(30)			,
	CUSTOM_2		varchar2(30)	  		,
	CUSTOM_3		varchar2(30)				
);

alter table AUTH_USER add constraint AUTH_USER_PK  primary key ( OBJID );
alter table AUTH_USER add constraint AUTH_USER_UK1 unique ( USER_EMAIL );
alter table AUTH_USER add constraint AUTH_USER_UK2 unique ( USER_LOGIN );

create index AUTH_USER_IDX2 on AUTH_USER ( USER_STATUS );


--
-- Table: AUTH_PASSWD_HISTORY
--
create table AUTH_PASSWD_HISTORY (
	USER_OBJID		integer			not null,
	MASKED_PASSWD	varchar2(128)	not null,
	INSERT_DATE		date			not null,
	EXPIRATION_DATE	date			not null,
	EXPIRATION_COUNT
			  		integer			not null,
	ERROR_COUNT		integer			default 0		not null,
	USED_COUNT		integer			default 0		not null,
	LAST_USED		date					,
	CUSTOM_1		varchar2(30)	  		,
	CUSTOM_2		varchar2(30)	  		,
	CUSTOM_3		varchar2(30)					
);
create index AUTH_PASSWD_HISTORY_IDX1 on AUTH_PASSWD_HISTORY ( USER_OBJID, INSERT_DATE );
create index AUTH_PASSWD_HISTORY_IDX2 on AUTH_PASSWD_HISTORY ( USER_OBJID, MASKED_PASSWD );


--
-- Table: AUTH_ROLE
--
create table AUTH_ROLE (
	OBJID			integer			not null,
	ROLE_NAME		varchar2(40)	not null,
	STATIC_CARDNLT	integer			not null,
	ROLE_STATUS		char(1)			not null,
	DESCRIPTION		varchar2(250)			,
	CUSTOM_1		varchar2(30)			,
	CUSTOM_2		varchar2(30)	  		,
	CUSTOM_3		varchar2(30)				
);
alter table AUTH_ROLE add constraint AUTH_ROLE_PK  primary key ( OBJID );
alter table AUTH_ROLE add constraint AUTH_ROLE_UK1 unique ( ROLE_NAME );

--
-- Table: AUTH_ROLE_HIERARCHY
--
create table AUTH_ROLE_HIERARCHY (
	ROLE_OBJID		integer 		not null,	
	PARENT_OBJID	integer			not null
);
alter table AUTH_ROLE_HIERARCHY add constraint AUTH_ROLE_HIERARCHY_PK  primary key ( ROLE_OBJID, PARENT_OBJID );
alter table AUTH_ROLE_HIERARCHY add constraint AUTH_ROLE_HIERARCHY_FK1 foreign key ( ROLE_OBJID ) references AUTH_ROLE ( OBJID );
alter table AUTH_ROLE_HIERARCHY add constraint AUTH_ROLE_HIERARCHY_FK2 foreign key ( PARENT_OBJID ) references AUTH_ROLE ( OBJID );


--
-- Table: AUTH_USER_ROLES
--
create table AUTH_USER_ROLES (
	USER_OBJID		integer			not null,
	ROLE_OBJID		integer 		not null,
	ASSIGN_DATE		date			not null,
	EXPIRATION_DATE	date
);
alter table AUTH_USER_ROLES add constraint AUTH_USER_ROLES_PK  primary key ( USER_OBJID, ROLE_OBJID, ASSIGN_DATE );
alter table AUTH_USER_ROLES add constraint AUTH_USER_ROLES_FK1 foreign key ( USER_OBJID ) references AUTH_USER ( OBJID );
alter table AUTH_USER_ROLES add constraint AUTH_USER_ROLES_FK2 foreign key ( ROLE_OBJID ) references AUTH_ROLE ( OBJID );

create index AUTH_USER_ROLES_IDX1 on AUTH_USER_ROLES ( ROLE_OBJID, USER_OBJID, ASSIGN_DATE );


--
-- Table: AUTH_ROLE_CONFLICT
--
create table AUTH_ROLE_CONFLICT (
	ROLE1_OBJID		integer			not null,
	ROLE2_OBJID		integer 		not null
);

alter table AUTH_ROLE_CONFLICT add constraint AUTH_ROLE_CONFLICT_PK  primary key ( ROLE1_OBJID, ROLE2_OBJID );
alter table AUTH_ROLE_CONFLICT add constraint AUTH_ROLE_CONFLICT_FK1 foreign key ( ROLE1_OBJID ) references AUTH_ROLE ( OBJID );
alter table AUTH_ROLE_CONFLICT add constraint AUTH_ROLE_CONFLICT_FK2 foreign key ( ROLE2_OBJID ) references AUTH_ROLE ( OBJID );

create index AUTH_ROLE_CONFLICT_IDX1 on AUTH_ROLE_CONFLICT ( ROLE2_OBJID, ROLE1_OBJID );


--
-- Table: AUTH_DOMAIN
--
create table AUTH_DOMAIN (
	OBJID			integer			not null,
	DOMAIN_NAME		varchar2(40)	not null,
	DOMAIN_STATUS	char(1)			not null,
	DESCRIPTION		varchar2(250)			,
	CUSTOM_1		varchar2(30)			,
	CUSTOM_2		varchar2(30)	  		,
	CUSTOM_3		varchar2(30)				
);
alter table AUTH_DOMAIN add constraint AUTH_DOMAIN_PK  primary key ( OBJID );
alter table AUTH_DOMAIN add constraint AUTH_DOMAIN_UK1 unique ( DOMAIN_NAME );


--
-- Table: AUTH_DOMAIN_ROLES
--
create table AUTH_DOMAIN_ROLES (
	DOMAIN_OBJID	integer			not null,
	ROLE_OBJID		integer 		not null,
	ASSIGN_DATE		date			not null,
	EXPIRATION_DATE	date
);
alter table AUTH_DOMAIN_ROLES add constraint AUTH_DOMAIN_ROLES_PK  primary key ( DOMAIN_OBJID, ROLE_OBJID, ASSIGN_DATE );
alter table AUTH_DOMAIN_ROLES add constraint AUTH_DOMAIN_ROLES_FK1 foreign key ( DOMAIN_OBJID ) references AUTH_DOMAIN ( OBJID );
alter table AUTH_DOMAIN_ROLES add constraint AUTH_DOMAIN_ROLES_FK2 foreign key ( ROLE_OBJID ) references AUTH_ROLE ( OBJID );

create index AUTH_DOMAIN_ROLES_IDX1 on AUTH_DOMAIN_ROLES ( ROLE_OBJID, DOMAIN_OBJID, ASSIGN_DATE );



create sequence AUTH_SEQUENCE start with 1 increment by 1;
