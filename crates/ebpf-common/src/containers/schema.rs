diesel::table! {
    #[sql_name = "ContainerConfig"]
    libpod_db_container_config (id) {
        #[sql_name = "ID"]
        id -> Text,
        #[sql_name = "Name"]
        name -> Text,
        #[sql_name = "PodID"]
        pod_id -> Text,
        #[sql_name = "JSON"]
        json -> Text,
    }
}
