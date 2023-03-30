/**
 * This is a C++ port of distance.py from
 * https://github.com/aflgo/aflgo/blob/master/scripts/distance.py
 *
 * Loris Reiff <loris.reiff@liblor.ch>
 */

#include "dyncfg.h"
#include "config.h"
#include <jsoncpp/json/writer.h>



enum {
    /* 00 */ MODE_CFG,
    /* 01 */ MODE_CG
};

/* global variables for cfg mode */
std::map<std::string, std::uint32_t> bug_targets;
std::map<std::string, std::string> fcalls;
std::vector<std::string> functions;
std::string first_bbname;

/* global variables for cg mode */
std::string temporary_dir;


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
    bo::dynamic_properties dp(bo::ignore_other_properties);
    dp.property("name", bo::get(&Vertex_cfg::name, graph));
    dp.property("bug_id", bo::get(&Vertex_cfg::bug_id, graph));
    dp.property("is_bcmp", bo::get(&Vertex_cfg::is_bcmp, graph));
    dp.property("is_fstbb", bo::get(&Vertex_cfg::is_fstbb, graph));
    dp.property("is_fcall", bo::get(&Vertex_cfg::is_fcall, graph));
    dp.property("fname", bo::get(&Vertex_cfg::fname, graph));
    dp.property("distance", bo::get(&Vertex_cfg::distance, graph));
    dp.property("node_id", bo::get(&Vertex_cfg::node_id, graph));



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
    bo::dynamic_properties dp(bo::ignore_other_properties);
    dp.property("name", bo::get(&Vertex_cfg::name, graph));
    dp.property("bug_id", bo::get(&Vertex_cfg::bug_id, graph));
    dp.property("is_bcmp", bo::get(&Vertex_cfg::is_bcmp, graph));
    dp.property("is_fstbb", bo::get(&Vertex_cfg::is_fstbb, graph));
    dp.property("is_fcall", bo::get(&Vertex_cfg::is_fcall, graph));
    dp.property("fname", bo::get(&Vertex_cfg::fname, graph));
    dp.property("distance", bo::get(&Vertex_cfg::distance, graph));
    dp.property("node_id", bo::get(&Vertex_cfg::node_id, graph));


    dp.property("edge_weight", bo::get(&Edge_cfg::edge_weight, graph));
    dp.property("bug_id", bo::get(&Edge_cfg::bug_id, graph));
    dp.property("is_bedge", bo::get(&Edge_cfg::is_bedge, graph));
    
    std::ifstream cfg = open_file(fname);
    read_graphviz(cfg, graph, dp);
    // return graph;
}


void load_cg_file(std::string const &fname, graph_cg_t &graph) {
    // graph_cg_t graph(0);
    bo::dynamic_properties dp(bo::ignore_other_properties);
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
    bo::dynamic_properties dp(bo::ignore_other_properties);
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


bool load_llvm_cfg(std::string const &fname, graph_llvm_t &graph_llvm) {
    std::ifstream fllvm = open_file(fname);
    cout << "Parsing " << fname << " ..\n";
    // graph_llvm_t graph_llvm(0);
    bo::dynamic_properties dp(bo::ignore_other_properties);
    // dp.property("node_id", get(&Vertex_llvm::name,  graph_llvm));
    dp.property("label",   get(&Vertex_llvm::label, graph_llvm));
    dp.property("shape",   get(&Vertex_llvm::shape, graph_llvm));
    dp.property("label",   get(&Edge_llvm::label,   graph_llvm));
    bo::ref_property_map<graph_llvm_t *, std::string> gname(get_property(graph_llvm, bo::graph_name));
    dp.property("label",    gname);

    if (!read_graphviz(fllvm, graph_llvm, dp)) {
        cerr << "Error while parsing " << fname << std::endl;
        return false;
    }
    return true;
}


bool cfg_has_vertex(std::string &vname, graph_cfg_t &cfg) {
    bool has_v = false;
    for (auto iter : boost::make_iterator_range(vertices(cfg))) {
        if (cfg[iter].name.compare(vname) == 0) {
            has_v = true;
            break;
        }
    }
    return has_v;
}

/* helper function for cfg construction */
vertex_desc_cfg initialized_cfg_vertex(Vertex_llvm v, graph_cfg_t &cfg) {
    /* if exist, just find and return */
    for (auto iter : boost::make_iterator_range(vertices(cfg))) {
        if (cfg[iter].name.compare(v.label) == 0) {
            return iter;
        }
    }

    auto vd =  bo::add_vertex(cfg);
    cfg[vd].name = v.label.substr(1, v.label.find("}") - 1);
    cfg[vd].node_id = cfg[vd].name;

    cfg[vd].distance = 0;
    // one bb might have several fcalls...
    std::map<std::string, std::string>::iterator f_iter = fcalls.find(cfg[vd].name);
    if (f_iter != fcalls.end()) {
        cfg[vd].is_fcall = true;
        cfg[vd].fname = f_iter->second; 
        // cfg[vd].fname = f_iter->second.substr(0, f_iter->second.find_last_of('.'));
    }
    else {
        cfg[vd].is_fcall = false;
        cfg[vd].fname = "";
    }

    auto biter = bug_targets.find(cfg[vd].name);
    if (biter != bug_targets.end()) {
        cfg[vd].is_bcmp = true;
        cfg[vd].bug_id = biter->second;
    }
    else {
        cfg[vd].is_bcmp = false;
        cfg[vd].bug_id = -1;
    }

    if (cfg[vd].name.compare(first_bbname) == 0) cfg[vd].is_fstbb = true;
    else cfg[vd].is_fstbb = false;

    return vd;
}

void initialized_cfg_edge(Edge_cfg &e, Vertex_cfg &vsrc, Vertex_cfg &vdst, bool is_single) {
    e.edge_weight = (is_single) ? 0 : 1;
    e.is_bedge = vsrc.is_bcmp;
    /* if is_bedge, then bug_id, else -1 */
    e.bug_id = vsrc.bug_id;

}

void add_edge_to_cfg(Vertex_llvm src, Vertex_llvm dst, graph_cfg_t &cfg, bool is_single) {
    auto vd_src = initialized_cfg_vertex(src, cfg),
         vd_dst = initialized_cfg_vertex(dst, cfg);
    Edge_cfg e;
    initialized_cfg_edge(e, cfg[vd_src], cfg[vd_dst], is_single);
    // auto vd_src = bo::add_vertex(vsrc, cfg),
    //      vd_dst = bo::add_vertex(vdst, cfg);
    auto ed_edge = bo::add_edge(vd_src, vd_dst, cfg);
    cfg[ed_edge.first] = e;
}



bool initialized_cfg_distance(graph_cfg_t &new_cfg) {
    // std::uint32_t fst_id = 468236;
    /* first get entry point of the function */
    // cout << "initializing cfg distance ...\n";

    // std::string temp_path = prev_path + ".temp";

    
    // // graph_cfg_t new_cfg(0);
    // load_cfg_file(temp_path, new_cfg);
    // cout << "Loading " << temp_path << "...\n";
    
    bo::graph_traits<graph_cfg_t>::vertex_iterator vi, vi_end;
    vertex_desc_cfg fst_node = 0;
    for (bo::tie(vi, vi_end) = vertices(new_cfg); vi != vi_end; ++vi) {
        if (new_cfg[*vi].is_fstbb == true) {
            //name.compare(first_bbname) == 0) {
            fst_node = *vi;
            break;
        }
    }
    cout << "fst node name : " << new_cfg[fst_node].name << "\n"; 

    // std::vector<std::uint32_t> distances(bo::num_vertices(new_cfg), 0);
    std::vector<std::uint32_t> distances(bo::num_vertices(new_cfg), UNREACHABLE_DIST);
    // init_distances_from(cfg, fst_node, distances);
    // auto dist_pmap = bo::make_iterator_property_map(distances.begin(), get(bo::vertex_index, new_cfg));
    // auto vis = bo::make_bfs_visitor(bo::record_distances(dist_pmap, bo::on_tree_edge()));
    // bo::breadth_first_search(new_cfg, fst_node, bo::visitor(vis));

    std::vector<vertex_desc_cfg> preds(bo::num_vertices(new_cfg));
    auto idmap = get(boost::vertex_index, new_cfg);
    bo::dijkstra_shortest_paths(new_cfg, fst_node, boost::predecessor_map(&preds[0])
        .distance_map(boost::make_iterator_property_map(
            distances.begin(), idmap))
        .weight_map(boost::get(&Edge_cfg::edge_weight, new_cfg)));

    for (auto vd : boost::make_iterator_range(vertices(new_cfg))) {
        // if (distances[vd] == 0 && vd != fst_node) {
            // new_cfg[vd].distance = UNREACHABLE_DIST;
        // }
        // else 
            new_cfg[vd].distance = distances[vd];
    }
    cout << "Done initialized cfg distance.\n";
    // return new_cfg;
    return true;
}

/* expected to construct a callgraph for the function */
bool construct_cfg(std::string cfgname, std::string savename) {

    graph_llvm_t cfg_graph_llvm(0);
    load_llvm_cfg(cfgname, cfg_graph_llvm);
    /* iterate over */
    graph_cfg_t cfg_graph(0), new_cfg(0);

    if (bo::num_vertices(cfg_graph_llvm) == 1) {
        initialized_cfg_vertex(cfg_graph_llvm[0], cfg_graph);
        cerr << "Empty graph with " << bo::num_vertices(cfg_graph_llvm) << std::endl;
        return true;
    }


    for (auto src : boost::make_iterator_range(vertices(cfg_graph_llvm))) {
        // auto src = *iter;
        // cout << cfg_graph_llvm[src].label << ", " << out_degree(src, cfg_graph_llvm) << "\n";

        for (auto edge : make_iterator_range(bo::out_edges(src, cfg_graph_llvm))) {
            auto dst = target(edge, cfg_graph_llvm);
            // source(edge, graph), target(edge, graph)
            bool is_single = (bo::out_degree(src, cfg_graph_llvm) == 1) ? true : false;
            add_edge_to_cfg(cfg_graph_llvm[src], cfg_graph_llvm[dst], cfg_graph, is_single);
        }
    }

    /* DEBUG */
    for (auto src: boost::make_iterator_range(vertices(cfg_graph))) {
        // cout << cfg_graph[src].label << ", " << out_degree(src, cfg_graph) << "\n";
        for (auto edge : make_iterator_range(bo::out_edges(src, cfg_graph))) {
            auto dst = target(edge, cfg_graph);
            cout << "\t" <<  cfg_graph[src].name << "-->" << cfg_graph[dst].name << "\n";
        }
    }


    save_cfg_file(cfgname + ".temp", cfg_graph);
    load_cfg_file(cfgname + ".temp", new_cfg);

    // return initialized_cfg_distance(cfg_graph, cfgname, new_cfg);
    initialized_cfg_distance(new_cfg);
    save_cfg_file(savename, new_cfg);
    return true;
    
}



std::uint32_t get_vuln_count(graph_cfg_t &cfg) {
    std::uint32_t cnt = 0;
    for (auto src : boost::make_iterator_range(vertices(cfg))) {
        if (cfg[src].is_bcmp == true) cnt ++;
    }
    return cnt;
}

std::string get_first_bbname(graph_cfg_t &cfg) {
    for (auto src : boost::make_iterator_range(vertices(cfg))) 
        if (cfg[src].is_fstbb == true) return cfg[src].name;
    return "";
}

std::uint32_t get_func_distance(graph_cfg_t &cfg, std::string fname) {
    std::uint32_t shortest = UNREACHABLE_DIST;
    for (auto src : boost::make_iterator_range(vertices(cfg))) {
        if (cfg[src].is_fcall == false) continue;
        // if (cfg[src].fname.compare(fname) == 0) {
        if (cfg[src].fname.find(fname + ",") == 0 ||
            cfg[src].fname.find("," + fname + ",") != std::string::npos) {
            // cout << cfg[src].fname << ": " << cfg[src].distance << "\n";
            if (cfg[src].distance < shortest) 
                shortest = cfg[src].distance;
        }
    }
    return shortest;
}

vertex_desc_cg initialized_cg_vertex(std::string &fname, graph_cg_t &cg) {

    /* if exist, just find and return */
    for (auto iter : boost::make_iterator_range(vertices(cg))) {
        if (cg[iter].name.compare(fname) == 0) {   
            return iter;
        }
    }
    auto vd = bo::add_vertex(cg);
    cg[vd].name = fname;
    cg[vd].distance = 0;
    std::string cfg_file = temporary_dir + "/runtimes/cfg." + cg[vd].name + ".dot";
    load_cfg_file(cfg_file, cg[vd].cfg);
    cg[vd].node_id = fname;// get_first_bbname(cg[vd].cfg);
    // create a new file containing first bb id.
    // if (cg[vd].node_id == 0) 
    //     cout << fname << " has node_id 0\n";
    cg[vd].vuln_count = get_vuln_count(cg[vd].cfg);
    
    return vd;
}

bool initialized_cg_edge(std::string &srcfname, std::string &dstfname, graph_cg_t &cg) { 

    // bool has_vd_src = if_cfg_exists(temporary_dir + "/runtimes/cfg." + srcfname.substr(1, srcfname.length() - 2) + ".dot"),
    //      has_vd_dst = if_cfg_exists(temporary_dir + "/runtimes/cfg." + dstfname.substr(1, dstfname.length() - 2) + ".dot");
    // if (!has_vd_src) {
    //     cout << srcfname << "," << dstfname << " not exists!\n";
    //     return true;
    // }
    // else if (!has_vd_dst) { 
    //     cout << dstfname << " not exists!\n";
    //     initialized_cg_vertex(srcfname, cg);
    //     return true;
    // }
    // else {
        std::string sfname = srcfname.substr(1, srcfname.length() - 2),
                    dfname = dstfname.substr(1, dstfname.length() - 2);
        // check if sfname and dfname in the function list.
        if (std::find(functions.begin(), functions.end(), sfname) == functions.end() ||
            std::find(functions.begin(), functions.end(), dfname) == functions.end()) 
            return false;

        // vertex_desc_cg vd_src = initialized_cg_vertex(srcfname, cg),
                    //    vd_dst = initialized_cg_vertex(dstfname, cg);
        vertex_desc_cg vd_src = initialized_cg_vertex(sfname, cg),
                       vd_dst = initialized_cg_vertex(dfname, cg);        
        
        if (edge(vd_src, vd_dst, cg).second == true) 
            return edge(vd_src, vd_dst, cg).second;
        
        auto ed = bo::add_edge(vd_src, vd_dst, cg);
        // cout << "add edge between " << sfname << " to " << dfname << "\n";
        cg[ed.first].edge_id = cg[vd_src].node_id + "->" + cg[vd_dst].node_id;
        cg[ed.first].visit_cnt = 0;
        cg[ed.first].edge_weight = get_func_distance(cg[vd_src].cfg, cg[vd_dst].name);
        return ed.second;
    // }
}


bool initialized_cg_distance(graph_cg_t &cg, std::string &prev_path, graph_cg_t &new_cg) {
    std::string temp_path = prev_path + ".temp";

    save_cg_file(temp_path, cg);
    // graph_cg_t new_cg(0);
    load_cg_file(temp_path, new_cg);
    cout << "Loading " << temp_path << "...\n";
    
    bo::graph_traits<graph_cg_t>::vertex_iterator vi, vi_end;
    vertex_desc_cg fst_node = 0;
    for (bo::tie(vi, vi_end) = vertices(new_cg); vi != vi_end; ++vi) {
        if (new_cg[*vi].name.compare("main") == 0) {
            fst_node = *vi;
            break;
        }
    }
    cout << "fst node name : " << new_cg[fst_node].name << "\n"; 

    std::vector<std::uint32_t> distances(bo::num_vertices(new_cg), UNREACHABLE_DIST);
    // init_distances_from(cfg, fst_node, distances);
    // auto dist_pmap = bo::make_iterator_property_map(distances.begin(), get(bo::vertex_index, new_cfg));
    // auto vis = bo::make_bfs_visitor(bo::record_distances(dist_pmap, bo::on_tree_edge()));
    // bo::breadth_first_search(new_cfg, fst_node, bo::visitor(vis));

    std::vector<vertex_desc_cg> preds(bo::num_vertices(new_cg));
    auto idmap = get(boost::vertex_index, new_cg);
    bo::dijkstra_shortest_paths(new_cg, fst_node, boost::predecessor_map(&preds[0])
        .distance_map(boost::make_iterator_property_map(
            distances.begin(), idmap))
        .weight_map(bo::get(&Edge_cg::edge_weight, new_cg)));

    for (auto vd : boost::make_iterator_range(vertices(new_cg))) {
        // if (distances[vd] == 0 && vd != fst_node) {
        //     new_cg[vd].distance = UNREACHABLE_DIST;
        // }
        // if (new_cg[vd].distance != -1) 
        // else 
            new_cg[vd].distance = distances[vd];
    }

    printf ("[DEBUG] finish initializing\n");
    /* remove unreachable edges... */
    // for (auto edge : bo::make_iterator_range(edges(new_cg))) {
    //     if (cg[edge].edge_weight == UNREACHABLE_DIST) {
    //         auto src = source(edge, new_cg),
    //              dst = target(edge, new_cg);
    //         bo::remove_edge(src, dst, new_cg);
    //     }
    // }

    // return new_cg;
    return true;
}

bool construct_cg(std::string cgname, graph_cg_t &cg_graph, graph_cg_t &new_cg) {
    graph_llvm_t cg_graph_llvm(0);
    load_llvm_cfg(cgname, cg_graph_llvm);

    // graph_cg_t cg_graph(0);

    if (bo::num_vertices(cg_graph_llvm) == 1) {
        initialized_cg_vertex(cg_graph_llvm[0].label, cg_graph);
        cerr << "Empty graph with " << bo::num_vertices(cg_graph_llvm) << std::endl;
        // return cg_graph;
        return true;
    }

    /* iterate over the cg and create edges */
    for (auto src : boost::make_iterator_range(vertices(cg_graph_llvm))) {
        for (auto edge : make_iterator_range(bo::out_edges(src, cg_graph_llvm))) {
            auto dst = target(edge, cg_graph_llvm);   
            cerr << "initialized cg with " << cg_graph_llvm[src].label 
                 << "->" << cg_graph_llvm[dst].label << "\n";
            initialized_cg_edge(cg_graph_llvm[src].label, cg_graph_llvm[dst].label, cg_graph);
        }
    }
    return initialized_cg_distance(cg_graph, cgname, new_cg);
}

bool calc_and_save_map(std::string temporary_dir, graph_cg_t &cg_graph) {

    // std::map<std::size_t, std::map<std::size_t, uint32_t>> shortest_func_dist;
    Json::Value shortest_func_dist, shortest_dst_to_src;
    for (auto vd_start : boost::make_iterator_range(vertices(cg_graph))) {
        std::vector<std::uint32_t> distances(bo::num_vertices(cg_graph), UNREACHABLE_DIST);

        std::vector<vertex_desc_cg> preds(bo::num_vertices(cg_graph));
        auto idmap = get(boost::vertex_index, cg_graph);
        // search start from vd
        bo::dijkstra_shortest_paths(cg_graph, vd_start, boost::predecessor_map(&preds[0])
            .distance_map(boost::make_iterator_property_map(
                distances.begin(), idmap))
            .weight_map(bo::get(&Edge_cg::edge_weight, cg_graph)));
        
        // take distances[vd] as distance
        // std::map<std::size_t, uint32_t> func_distance;
        Json::Value func_distance;
        for (auto vd : boost::make_iterator_range(vertices(cg_graph))) {
            // if (distances[vd] != UNREACHABLE_DIST)
	    if (distances[vd] < UNREACHABLE_DIST / 2)
                if (!(distances[vd] == 0 && vd == vd_start)) {
                    // don't store itself
                    func_distance[std::to_string(vd)] = distances[vd];
                    if (shortest_dst_to_src.isMember(std::to_string(vd))) {
                        Json::Value func_dist = shortest_dst_to_src[std::to_string(vd)];
                        func_dist[std::to_string(vd_start)] = distances[vd];
                        shortest_dst_to_src[std::to_string(vd)] = func_dist;
                    }
                    else {
                        Json::Value func_dist;
                        func_dist[std::to_string(vd_start)] = distances[vd];
                        shortest_dst_to_src[std::to_string(vd)] = func_dist;
                    }
                }
        }
        shortest_func_dist[std::to_string(vd_start)] = func_distance;
    }

    // std::cout << shortest_func_dist << std::endl;
    /* format src_func: {dst_func : distance} */
    std::ofstream distance_map(temporary_dir + "/runtimes/callmap.json");
    Json::StyledWriter styledWriter;
    distance_map << styledWriter.write(shortest_func_dist);
    distance_map.close();
    /* format dst_func: {src_func : distance} */
    std::ofstream dst_to_src_map(temporary_dir + "/runtimes/calldst.json");
    Json::StyledWriter styledWriter1;
    dst_to_src_map << styledWriter1.write(shortest_dst_to_src);
    dst_to_src_map.close();

    return true;
}


/* helper function for cg construction */

int main(int argc, char *argv[]) {
    po::variables_map vm;
    try {
        po::options_description desc("prefuzz parsing callgraph and cfg");
        desc.add_options()
                ("help,h", "produce help message")
                ("dot,d", po::value<std::string>()->required(), "Path to dot-file representing the "
                                                           "control flow graph.")
                ("temp,t", po::value<std::string>()->required(), "Temporary folder contain dot "
                                                                    "files.")
                ("out,o", po::value<std::string>()->required(), "Path to out-file contain dot files "
                                                                    "with initial distance.")
                ("outmap,a", po::value<std::string>(), "Path to out-file contain shortest "
                                                                    "function distance.")
                ("mode,m", po::value<std::string>()->required(), "Run in cfg mode or cg mode.")
                ;

        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            cout << desc << "\n";
            return 0;
        }
        po::notify(vm);
    }
    catch(exception& e) {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }
    catch(...) {
        cerr << "Exception of unknown type!\n";
    }

    temporary_dir = vm["temp"].as<std::string>();
    std::string mode_str = vm["mode"].as<std::string>();
    std::uint32_t mode;
    if (mode_str.compare("cfg") == 0) {
        mode = MODE_CFG;
        cout << "Run in cfg mode !\n";
    }
    else if (mode_str.compare("cg") == 0) {
        mode = MODE_CG;
        cout << "Run in cg mode !\n";
    }
    else {
        cout << "unknown mode, specify cg/cfg instead!";
        return 0;
    }

    if (mode == MODE_CFG) {

        std::string cfg_file = vm["dot"].as<std::string>();
        std::string temporary_path = vm["temp"].as<std::string>();

        std::ifstream bt(temporary_path + "/bug_cmps.csv");
        std::uint32_t bug_id = 0;
        if (bt.is_open()) {
            std::string line;
            while (getline(bt, line))
                if (bug_targets.find(line) == bug_targets.end())
                    bug_targets.emplace(line, bug_id ++);
        }

        std::ifstream cm(temporary_path + "/callmap.csv");
        if (cm.is_open()) {
            std::string line;
            while (getline(cm, line)) {
                std::size_t fpos = line.find(","), fstbb_pos = line.rfind(",");
                std::string bbname = line.substr(0, fpos);
                std::string fname = line.substr(fpos + 1, fstbb_pos - fpos - 1);
                auto f_iter = fcalls.find(bbname);
                if (f_iter == fcalls.end())
                    fcalls.emplace(bbname, fname + ",");
                else 
                    f_iter->second = f_iter->second + fname + ",";

            }
        }
        std::ifstream fb(temporary_path + "/firstbb.csv");
        if (fb.is_open()) { 
            std::size_t pos1 = cfg_file.find("cfg."),
                        pos2 = cfg_file.find(".dot");
            std::string module_name = cfg_file.substr(pos1 + 4, pos2 - pos1 - 4);
            cout << "module name " << module_name << "\n";
            std::string line;
            graph_llvm_t test_cfg(0);
            load_llvm_cfg(vm["dot"].as<std::string>(), test_cfg);
            while (getline(fb, line)) {
                /* match bbname's module with real module name */
                std::size_t rpos = line.rfind(":"),
                            lpos = line.find(":");
                std::string bbname_module = line.substr(lpos + 1, rpos - lpos - 1);
                if (bbname_module.compare(module_name) == 0) { 
                    cout << bbname_module << ", " << line <<"\n";
                    // first_bbname = line.substr(fstbb_pos + 1, line.length() - fstbb_pos);
                    // for (auto src : boost::make_iterator_range(vertices(test_cfg))) {
                    //     if (test_cfg[src].label.compare("{" + line + "}") == 0)
                    //         first_bbname = line;
                    // }
                    first_bbname = line;
                }
                if (!first_bbname.empty()) break;
            }
        }
        cout << "first bb name is " << first_bbname << "\n";

        graph_cfg_t cfg(0), new_cfg(0);
        // construct_cfg(vm["dot"].as<std::string>(), cfg, new_cfg);
        construct_cfg(vm["dot"].as<std::string>(), vm["out"].as<std::string>());
        // save_cfg_file(vm["out"].as<std::string>(), cfg);
        // save_cfg_file(vm["out"].as<std::string>(), new_cfg);
    }
    
    else if (mode == MODE_CG) {
        /* generate both runtime/callgraph.dot and distance map */
        std::string temporary_path = vm["temp"].as<std::string>();
        std::ifstream fb(temporary_path + "/funcmap.csv");
        if (fb.is_open()) { 
            std::string line;
            while (getline(fb, line)) {
                functions.push_back(line);
            }
        }
        graph_cg_t cg(0), new_cg(0);
        construct_cg(vm["dot"].as<std::string>(), cg, new_cg);
        save_cg_file(vm["out"].as<std::string>(), new_cg);
        /* calculate distance file, map format : 
            map<src_func, map<dst_func, distance>> */
        calc_and_save_map(vm["temp"].as<std::string>(), new_cg);
        std::ofstream fi(vm["temp"].as<std::string>() + "/funcid.csv");
        for (auto vert : bo::make_iterator_range(vertices(new_cg))) {
            fi << vert << "," << new_cg[vert].name << "\n";
        }
    }


    return 0;
}
