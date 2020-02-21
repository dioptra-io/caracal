//
// Created by System Administrator on 2019-07-12.
//

#include <clickhouse_t.hpp>
#include <iostream>
#include <algorithm>
#include <memory>
int main(int argc, char **argv) {


    auto history_versions = 3;
    auto max_dynamics = history_versions;

    std::vector<std::unique_ptr<std::ofstream>> ostreams;

    for (int i = 0; i < max_dynamics; ++i){

        ostreams.emplace_back(std::make_unique<std::ofstream>(std::ofstream()));
        std::stringstream s;
        s << "resources/probes_dynamics_" << i << ".csv";
        ostreams[i]->open(s.str());
    }


    clickhouse_t clickhouse("132.227.123.200");


    clickhouse.next_snapshot("heartbeat.versioned_probes", current_version, history_versions, ostreams);


}
