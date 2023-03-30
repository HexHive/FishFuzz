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
    std::string name, fname, node_id;
    std::uint32_t distance, bug_id;
    bool is_bcmp, is_fcall, is_fstbb;
};
struct Edge_cfg {
    std::uint32_t edge_weight;
    std::uint32_t bug_id;
    bool is_bedge;
};
typedef bo::adjacency_list<bo::vecS, bo::vecS, bo::directedS, Vertex_cfg, Edge_cfg, graph_p> graph_cfg_t;
typedef bo::graph_traits<graph_cfg_t>::vertex_descriptor vertex_desc_cfg;

struct Vertex_cg {
    std::string name, node_id;
    std::uint32_t vuln_count, distance;
    graph_cfg_t cfg;
};
struct Edge_cg {
    std::string edge_id;
    std::uint32_t visit_cnt, edge_weight;
};
typedef bo::adjacency_list<bo::vecS, bo::vecS, bo::directedS, Vertex_cg, Edge_cg, graph_p> graph_cg_t;
typedef bo::graph_traits<graph_cg_t>::vertex_descriptor vertex_desc_cg;
typedef bo::graph_traits<graph_cg_t>::edge_descriptor edge_desc_cg;





#endif