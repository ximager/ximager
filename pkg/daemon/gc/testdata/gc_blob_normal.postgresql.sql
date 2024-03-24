INSERT INTO "daemon_gc_blob_rules" ("id", "is_running", "retention_day", "cron_enabled", "cron_rule", "cron_next_trigger", "created_at", "updated_at", "deleted_at")
  VALUES (1, 0, 0, 0, NULL, NULL, 1711288066277, 1711288066277, 0);

INSERT INTO "daemon_gc_blob_runners" ("id", "rule_id", "message", "status", "operate_type", "operate_user_id", "started_at", "ended_at", "duration", "success_count", "failed_count", "created_at", "updated_at", "deleted_at")
  VALUES (1, 1, NULL, 'Success', 'Manual', NULL, NULL, NULL, NULL, NULL, NULL, 1711288072580, 1711288072619, 0);

INSERT INTO "repositories" ("id", "name", "description", "overview", "size_limit", "size", "tag_limit", "tag_count", "namespace_id", "created_at", "updated_at", "deleted_at")
  VALUES (1, 'library/alpine', NULL, NULL, 0, 6594618, 0, 1, 1, 1711288021556, 1711288021556, 0);

INSERT INTO "artifacts" ("id", "repository_id", "digest", "size", "blobs_size", "content_type", "raw", "config_raw", "config_media_type", "type", "pushed_at", "last_pull", "pull_times", "referrer_id", "created_at", "updated_at", "deleted_at")
  VALUES (1, 1, 'sha256:24b42af5b7bdb9ccf1252e508ee0a4fd85eb3286a4596c422739ae6beb3038f4', 528, 3334848, 'application/vnd.docker.distribution.manifest.v2+json', '\x7b0a20202022736368656d6156657273696f6e223a20322c0a202020226d6564696154797065223a20226170706c69636174696f6e2f766e642e646f636b65722e646973747269627574696f6e2e6d616e69666573742e76322b6a736f6e222c0a20202022636f6e666967223a207b0a202020202020226d6564696154797065223a20226170706c69636174696f6e2f766e642e646f636b65722e636f6e7461696e65722e696d6167652e76312b6a736f6e222c0a2020202020202273697a65223a20313438372c0a20202020202022646967657374223a20227368613235363a33336162626630333231343932666637333739653630633235326330356334653765643464636366343666636361366335353830363763323565373664633862220a2020207d2c0a202020226c6179657273223a205b0a2020202020207b0a202020202020202020226d6564696154797065223a20226170706c69636174696f6e2f766e642e646f636b65722e696d6167652e726f6f7466732e646966662e7461722e677a6970222c0a2020202020202020202273697a65223a20333333333336312c0a20202020202020202022646967657374223a20227368613235363a63366233396465356233333936313636316463393339623939376363316433306364613031653338303035613663363632356664396337653734386261623434220a2020202020207d0a2020205d0a7d', '\x7b22617263686974656374757265223a2261726d3634222c22636f6e666967223a7b22486f73746e616d65223a22222c22446f6d61696e6e616d65223a22222c2255736572223a22222c22417474616368537464696e223a66616c73652c224174746163685374646f7574223a66616c73652c22417474616368537464657272223a66616c73652c22547479223a66616c73652c224f70656e537464696e223a66616c73652c22537464696e4f6e6365223a66616c73652c22456e76223a5b22504154483d2f7573722f6c6f63616c2f7362696e3a2f7573722f6c6f63616c2f62696e3a2f7573722f7362696e3a2f7573722f62696e3a2f7362696e3a2f62696e225d2c22436d64223a5b222f62696e2f7368225d2c22496d616765223a227368613235363a62323630376565366430303135623137373332653963666433656466366434386134303762626332336438623632656366346434613665643533663236623537222c22566f6c756d6573223a6e756c6c2c22576f726b696e67446972223a22222c22456e747279706f696e74223a6e756c6c2c224f6e4275696c64223a6e756c6c2c224c6162656c73223a6e756c6c7d2c22636f6e7461696e6572223a2234623430313935626363666461616431316464376662333638326337303130303835636265343661613333313762626561303463396539383261663237646635222c22636f6e7461696e65725f636f6e666967223a7b22486f73746e616d65223a22346234303139356263636664222c22446f6d61696e6e616d65223a22222c2255736572223a22222c22417474616368537464696e223a66616c73652c224174746163685374646f7574223a66616c73652c22417474616368537464657272223a66616c73652c22547479223a66616c73652c224f70656e537464696e223a66616c73652c22537464696e4f6e6365223a66616c73652c22456e76223a5b22504154483d2f7573722f6c6f63616c2f7362696e3a2f7573722f6c6f63616c2f62696e3a2f7573722f7362696e3a2f7573722f62696e3a2f7362696e3a2f62696e225d2c22436d64223a5b222f62696e2f7368222c222d63222c2223286e6f702920222c22434d44205b5c222f62696e2f73685c225d225d2c22496d616765223a227368613235363a62323630376565366430303135623137373332653963666433656466366434386134303762626332336438623632656366346434613665643533663236623537222c22566f6c756d6573223a6e756c6c2c22576f726b696e67446972223a22222c22456e747279706f696e74223a6e756c6c2c224f6e4275696c64223a6e756c6c2c224c6162656c73223a7b7d7d2c2263726561746564223a22323032342d30312d32365432333a34343a35352e3735303038323630355a222c22646f636b65725f76657273696f6e223a2232302e31302e3233222c22686973746f7279223a5b7b2263726561746564223a22323032342d30312d32365432333a34343a35352e3635303239303632365a222c22637265617465645f6279223a222f62696e2f7368202d632023286e6f7029204144442066696c653a3664633238376132326436636337373233623035373664643361396136343434363864313333633534643432633861386564613430336533313137363438663720696e202f20227d2c7b2263726561746564223a22323032342d30312d32365432333a34343a35352e3735303038323630355a222c22637265617465645f6279223a222f62696e2f7368202d632023286e6f70292020434d44205b5c222f62696e2f73685c225d222c22656d7074795f6c61796572223a747275657d5d2c226f73223a226c696e7578222c22726f6f746673223a7b2274797065223a226c6179657273222c22646966665f696473223a5b227368613235363a37633530346632316265383563386164653531623761646533326133396134323639626362636630653539333335323932336631623865613632373865356566225d7d2c2276617269616e74223a227638227d', 'application/vnd.docker.container.image.v1+json', 'Image', 1711288021563, 0, 0, NULL, 1711288021563, 1711288021563, 1711288063290),
  (2, 1, 'sha256:74440a3ca0e58af8aa796467285de45d0e079067c79200f2cfab30d6a38051d8', 528, 3259770, 'application/vnd.docker.distribution.manifest.v2+json', '\x7b0a20202022736368656d6156657273696f6e223a20322c0a202020226d6564696154797065223a20226170706c69636174696f6e2f766e642e646f636b65722e646973747269627574696f6e2e6d616e69666573742e76322b6a736f6e222c0a20202022636f6e666967223a207b0a202020202020226d6564696154797065223a20226170706c69636174696f6e2f766e642e646f636b65722e636f6e7461696e65722e696d6167652e76312b6a736f6e222c0a2020202020202273697a65223a20313438372c0a20202020202022646967657374223a20227368613235363a66306664386665313662666135353137396336356432303863653861626635383139376538353133366636613164633534336432313336343234666436363563220a2020207d2c0a202020226c6179657273223a205b0a2020202020207b0a202020202020202020226d6564696154797065223a20226170706c69636174696f6e2f766e642e646f636b65722e696d6167652e726f6f7466732e646966662e7461722e677a6970222c0a2020202020202020202273697a65223a20333235383238332c0a20202020202020202022646967657374223a20227368613235363a35333835613961353930633365323837326233656432373535346135366662376365353434633639346234316239623935643730666138366633306230353636220a2020202020207d0a2020205d0a7d', '\x7b22617263686974656374757265223a2261726d3634222c22636f6e666967223a7b22486f73746e616d65223a22222c22446f6d61696e6e616d65223a22222c2255736572223a22222c22417474616368537464696e223a66616c73652c224174746163685374646f7574223a66616c73652c22417474616368537464657272223a66616c73652c22547479223a66616c73652c224f70656e537464696e223a66616c73652c22537464696e4f6e6365223a66616c73652c22456e76223a5b22504154483d2f7573722f6c6f63616c2f7362696e3a2f7573722f6c6f63616c2f62696e3a2f7573722f7362696e3a2f7573722f62696e3a2f7362696e3a2f62696e225d2c22436d64223a5b222f62696e2f7368225d2c22496d616765223a227368613235363a32356662363165383438363731313139343739396131323262346366613430343165616237613365386234626434356333623537653234666531353933303464222c22566f6c756d6573223a6e756c6c2c22576f726b696e67446972223a22222c22456e747279706f696e74223a6e756c6c2c224f6e4275696c64223a6e756c6c2c224c6162656c73223a6e756c6c7d2c22636f6e7461696e6572223a2264333433356533353330333163356237343539646161373639383632636539633139323033363432633634336362393963633837633461613032633435343136222c22636f6e7461696e65725f636f6e666967223a7b22486f73746e616d65223a22643334333565333533303331222c22446f6d61696e6e616d65223a22222c2255736572223a22222c22417474616368537464696e223a66616c73652c224174746163685374646f7574223a66616c73652c22417474616368537464657272223a66616c73652c22547479223a66616c73652c224f70656e537464696e223a66616c73652c22537464696e4f6e6365223a66616c73652c22456e76223a5b22504154483d2f7573722f6c6f63616c2f7362696e3a2f7573722f6c6f63616c2f62696e3a2f7573722f7362696e3a2f7573722f62696e3a2f7362696e3a2f62696e225d2c22436d64223a5b222f62696e2f7368222c222d63222c2223286e6f702920222c22434d44205b5c222f62696e2f73685c225d225d2c22496d616765223a227368613235363a32356662363165383438363731313139343739396131323262346366613430343165616237613365386234626434356333623537653234666531353933303464222c22566f6c756d6573223a6e756c6c2c22576f726b696e67446972223a22222c22456e747279706f696e74223a6e756c6c2c224f6e4275696c64223a6e756c6c2c224c6162656c73223a7b7d7d2c2263726561746564223a22323032342d30312d32365432333a34353a30302e3631313336323335395a222c22646f636b65725f76657273696f6e223a2232302e31302e3233222c22686973746f7279223a5b7b2263726561746564223a22323032342d30312d32365432333a34353a30302e3530373337343539385a222c22637265617465645f6279223a222f62696e2f7368202d632023286e6f7029204144442066696c653a6333623662353735656237343166393134656331326264346466343364653063623034346131663262616537666631356431373665343962353938366439303320696e202f20227d2c7b2263726561746564223a22323032342d30312d32365432333a34353a30302e3631313336323335395a222c22637265617465645f6279223a222f62696e2f7368202d632023286e6f70292020434d44205b5c222f62696e2f73685c225d222c22656d7074795f6c61796572223a747275657d5d2c226f73223a226c696e7578222c22726f6f746673223a7b2274797065223a226c6179657273222c22646966665f696473223a5b227368613235363a34353865636438646163363733396265373431303036353034623166653138376464613535616239656231323465376364373964356631633962623734393735225d7d2c2276617269616e74223a227638227d', 'application/vnd.docker.container.image.v1+json', 'Image', 1711288027580, 0, 0, NULL, 1711288027580, 1711288027580, 0);

INSERT INTO "tags" ("id", "repository_id", "artifact_id", "name", "pushed_at", "last_pull", "pull_times", "created_at", "updated_at", "deleted_at")
  VALUES (1, 1, 2, '3.18', 1711288021567, 0, 0, 1711288021567, 1711288027582, 0);

INSERT INTO "blobs" ("id", "digest", "size", "content_type", "pushed_at", "last_pull", "pull_times", "created_at", "updated_at", "deleted_at")
  VALUES (1, 'sha256:c6b39de5b33961661dc939b997cc1d30cda01e38005a6c6625fd9c7e748bab44', 3333361, '', 1711288021492, 0, 0, 1711288021492, 1711288021492, 0),
  (2, 'sha256:33abbf0321492ff7379e60c252c05c4e7ed4dccf46fcca6c558067c25e76dc8b', 1487, '', 1711288021544, 0, 0, 1711288021544, 1711288021544, 0),
  (3, 'sha256:5385a9a590c3e2872b3ed27554a56fb7ce544c694b41b9b95d70fa86f30b0566', 3258283, '', 1711288027527, 0, 0, 1711288027527, 1711288027527, 0),
  (4, 'sha256:f0fd8fe16bfa55179c65d208ce8abf58197e85136f6a1dc543d2136424fd665c', 1487, '', 1711288027566, 0, 0, 1711288027566, 1711288027566, 0);

INSERT INTO "artifact_blobs" ("artifact_id", "blob_id")
  VALUES (1, 1),
  (1, 2),
  (2, 3),
  (2, 4);

