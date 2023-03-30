#ifndef _PREFUZZ_DYNCFG_H
#define _PREFUZZ_DYNCFG_H

#include <boost/program_options.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>

// #define UNREACHABLE_SIZE 0xFFFFFFFF

namespace po = boost::program_options;
namespace bo = boost;
using std::cout;
using std::cerr;
using std::exception;
using std::unordered_map;


struct Vertex_llvm {
    std::string name, label, shape;
};

struct Edge_llvm {
    std::string label;
};

typedef bo::property<bo::graph_name_t, std::string> graph_p;
typedef bo::adjacency_list<bo::vecS, bo::vecS, bo::directedS, Vertex_llvm, Edge_llvm, graph_p> graph_llvm_t;
typedef bo::graph_traits<graph_llvm_t>::vertex_descriptor vertex_desc_llvm;


struct Vertex_cfg {
    std::string name, fname;
    std::uint32_t node_id, distance, bug_id;
    bool is_bcmp, is_fcall, is_fstbb;
};
struct Edge_cfg {
    std::uint32_t edge_id, visit_cnt, edge_weight;
    std::uint32_t bug_id;
    bool is_bedge;
};
typedef bo::adjacency_list<bo::vecS, bo::vecS, bo::directedS, Vertex_cfg, Edge_cfg, graph_p> graph_cfg_t;
typedef bo::graph_traits<graph_cfg_t>::vertex_descriptor vertex_desc_cfg;

struct Vertex_cg {
    std::string name;
    std::uint32_t node_id, vuln_count, distance;
    graph_cfg_t cfg;
};
struct Edge_cg {
    std::uint32_t edge_id, visit_cnt, edge_weight;
};
typedef bo::adjacency_list<bo::vecS, bo::vecS, bo::directedS, Vertex_cg, Edge_cg, graph_p> graph_cg_t;
typedef bo::graph_traits<graph_cg_t>::vertex_descriptor vertex_desc_cg;
typedef bo::graph_traits<graph_cg_t>::edge_descriptor edge_desc_cg;



bool if_cfg_exists(std::string const &fname) {
    std::ifstream f(fname.c_str());
    return f.good();
}

std::ifstream open_file(const std::string &filename) {
    std::ifstream filestream(filename);
    if (not filestream) {
        cerr << "Error: " << strerror(errno) << ": " << filename << "\n";
        exit(1);
    }
    return filestream;
}


void save_cfg_file(std::string const& fname, graph_cfg_t& graph) {
    bo::dynamic_properties dp;
    dp.property("name", bo::get(&Vertex_cfg::name, graph));
    dp.property("node_id", bo::get(&Vertex_cfg::node_id, graph));
    dp.property("bug_id", bo::get(&Vertex_cfg::bug_id, graph));
    dp.property("is_bcmp", bo::get(&Vertex_cfg::is_bcmp, graph));
    dp.property("is_fstbb", bo::get(&Vertex_cfg::is_fstbb, graph));
    dp.property("is_fcall", bo::get(&Vertex_cfg::is_fcall, graph));
    dp.property("fname", bo::get(&Vertex_cfg::fname, graph));
    dp.property("distance", bo::get(&Vertex_cfg::distance, graph));


    dp.property("edge_id", bo::get(&Edge_cfg::edge_id, graph));
    dp.property("visit_cnt", bo::get(&Edge_cfg::visit_cnt, graph));
    dp.property("edge_weight", bo::get(&Edge_cfg::edge_weight, graph));
    dp.property("bug_id", bo::get(&Edge_cfg::bug_id, graph));
    dp.property("is_bedge", bo::get(&Edge_cfg::is_bedge, graph));

    std::ofstream ofs(fname);
    write_graphviz_dp(ofs, graph, dp);
    cout << "write to " << fname << "...\n";
}


void load_cfg_file(std::string const& fname, graph_cfg_t &graph) {
    if (!if_cfg_exists(fname)) {
        cout << "cfg " << fname << " not exisits!\n";
        return ;
    }
    // graph_cfg_t graph(0);
    bo::dynamic_properties dp;
    dp.property("name", bo::get(&Vertex_cfg::name, graph));
    dp.property("node_id", bo::get(&Vertex_cfg::node_id, graph));
    dp.property("bug_id", bo::get(&Vertex_cfg::bug_id, graph));
    dp.property("is_bcmp", bo::get(&Vertex_cfg::is_bcmp, graph));
    dp.property("is_fstbb", bo::get(&Vertex_cfg::is_fstbb, graph));
    dp.property("is_fcall", bo::get(&Vertex_cfg::is_fcall, graph));
    dp.property("fname", bo::get(&Vertex_cfg::fname, graph));
    dp.property("distance", bo::get(&Vertex_cfg::distance, graph));


    dp.property("edge_id", bo::get(&Edge_cfg::edge_id, graph));
    dp.property("visit_cnt", bo::get(&Edge_cfg::visit_cnt, graph));
    dp.property("edge_weight", bo::get(&Edge_cfg::edge_weight, graph));
    dp.property("bug_id", bo::get(&Edge_cfg::bug_id, graph));
    dp.property("is_bedge", bo::get(&Edge_cfg::is_bedge, graph));
    
    std::ifstream cfg = open_file(fname);
    read_graphviz(cfg, graph, dp);
    // return graph;
}


void load_cg_file(std::string const &fname, graph_cg_t &graph) {
    // graph_cg_t graph(0);
    bo::dynamic_properties dp;
    dp.property("name", bo::get(&Vertex_cg::name, graph));
    dp.property("node_id", bo::get(&Vertex_cg::node_id, graph));
    dp.property("vuln_count", bo::get(&Vertex_cg::vuln_count, graph));
    dp.property("distance", bo::get(&Vertex_cg::distance, graph));


    dp.property("edge_id", bo::get(&Edge_cg::edge_id, graph));
    dp.property("visit_cnt", bo::get(&Edge_cg::visit_cnt, graph));
    dp.property("edge_weight", bo::get(&Edge_cg::edge_weight, graph));
    std::ifstream cg = open_file(fname);
    read_graphviz(cg, graph, dp);
    // return graph;
}

void save_cg_file(std::string const& fname, graph_cg_t& graph) {
    bo::dynamic_properties dp;
    dp.property("name", bo::get(&Vertex_cg::name, graph));
    dp.property("node_id", bo::get(&Vertex_cg::node_id, graph));
    dp.property("vuln_count", bo::get(&Vertex_cg::vuln_count, graph));
    dp.property("distance", bo::get(&Vertex_cg::distance, graph));


    dp.property("edge_id", bo::get(&Edge_cg::edge_id, graph));
    dp.property("visit_cnt", bo::get(&Edge_cg::visit_cnt, graph));
    dp.property("edge_weight", bo::get(&Edge_cg::edge_weight, graph));

    std::ofstream ofs(fname);
    write_graphviz_dp(ofs, graph, dp);
    cout << "write to " << fname << "...\n";
}



#endif