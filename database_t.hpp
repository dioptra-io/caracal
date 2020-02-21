//
// Created by System Administrator on 2019-02-06.
//

#ifndef HEARTBEAT_DATABASE_T_HPP
#define HEARTBEAT_DATABASE_T_HPP

#include <pqxx/pqxx>
class database_t {
public:
    database_t();

    pqxx::connection & get_connection();

private:
    pqxx::connection m_connection;
};


#endif //HEARTBEAT_DATABASE_T_HPP
