DROP TABLE black_ip_list;
CREATE TABLE "black_ip_list" (
	`ix`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	`host_ix`	INTEGER NOT NULL UNIQUE,
	`timestamp`	INTEGER NOT NULL,
	FOREIGN KEY(`host_ix`) REFERENCES `hosts_table`(`ix`)
);

