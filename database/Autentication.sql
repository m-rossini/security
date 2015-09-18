create table AUT_USER (
   cd_user  varchar(8) NOT NULL PRIMARY KEY,
   tx_password char(32),
   nm_user varchar(32),
   dt_create timestamp NOT NULL,
   dt_last_access timestamp,
   qt_logins SMALLINT,
   dt_status timestamp NOT NULL,
   st_status CHAR(1) NOT NULL, 
   cd_user_last_update varchar(8) NOT NULL
);

CREATE INDEX IDX_USER_STATUS ON AUT_USER (ST_STATUS, DT_STATUS);

create table AUT_GROUP (
   cd_group INTEGER NOT NULL PRIMARY KEY,
   nm_group VARCHAR(32) NOT NULL,
   dt_create timestamp NOT NULL,
   dt_status timestamp NOT NULL,
   st_status CHAR(1) NOT NULL,
   cd_user_last_update varchar(8) NOT NULL
);

CREATE INDEX IDX_GROUP_NAME ON AUT_GROUP (NM_GROUP);

CREATE INDEX IDX_GROUP_STATUS ON AUT_GROUP (ST_STATUS, DT_STATUS);

CREATE TABLE AUT_PERM (
   cd_perm INTEGER NOT NULL primary key,
   nm_perm VARCHAR(32),
   tx_desc VARCHAR(256)
);
   
CREATE INDEX IDX_NM_PERM ON AUT_PERM (NM_PERM);

CREATE TABLE AUT_USER_GROUP_ASGM (
   cd_user VARCHAR(8) NOT NULL,
   cd_group INTEGER NOT NULL,
   dt_asgm timestamp NOT NULL,
   dt_expr timestamp,
   cd_user_last_update VARCHAR(8) NOT NULL,
   PRIMARY KEY(cd_user,cd_group,dt_asgm)
);

ALTER TABLE AUT_USER_GROUP_ASGM 
  ADD CONSTRAINT AUT_USER_GROUP_USER_FK FOREIGN KEY (cd_user) 
      REFERENCES AUT_USER (cd_user);

ALTER TABLE AUT_USER_GROUP_ASGM 
  ADD CONSTRAINT AUT_USER_GROUP_GROUP_FK FOREIGN KEY (cd_group) 
      REFERENCES AUT_GROUP (cd_group);

CREATE TABLE AUT_GROUP_PERM_ASGM (
   cd_group INTEGER NOT NULL,
   cd_perm INTEGER NOT NULL,
   dt_asgm timestamp NOT NULL,
   dt_expr timestamp,
   cd_user_last_update VARCHAR(8) NOT NULL,
   PRIMARY KEY(cd_group,cd_perm,dt_asgm)
);

ALTER TABLE AUT_GROUP_PERM_ASGM 
  ADD CONSTRAINT AUT_GROUP_PERM_GROUP_FK FOREIGN KEY (cd_group) 
      REFERENCES AUT_GROUP (cd_group);

ALTER TABLE AUT_GROUP_PERM_ASGM 
  ADD CONSTRAINT AUT_GROUP_PERM_PERM_FK FOREIGN KEY (cd_perm) 
      REFERENCES AUT_PERM (cd_perm);


