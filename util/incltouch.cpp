#include<chrono>
#include<experimental/filesystem>
#include<fstream>
#include<regex>
#include<string>
#include"graph.h"
using namespace std;
using namespace experimental::filesystem;

void recur_touch(Vertex<path> *p) {
	if(p->v) return;
	p->v = 1;
	for(auto *e = p->edge; e; e = e->edge) {
		if(last_write_time(e->vertex->data) < last_write_time(p->data))
			last_write_time(e->vertex->data, last_write_time(p->data));
		recur_touch(e->vertex);//only first apply 
	}
}

int main()
{//make header include tree -> if header is modified, change the including file access time
	const char *ext[] = {".cpp", ".cc", ".h", ".hpp"};
	Graph<path> gr;
	regex rx{R"head(#include\s*"(\S+)")head"};
	for(auto a : directory_iterator{"."}) if(is_directory(a))
	for(const path& b : directory_iterator{a})
	for(auto *c : ext) if(b.extension() == c) {
		ifstream f{b}; string s;//open files with extension of ext in sub directory
		for(char c; f >> noskipws >> c;) s += c;
		for(smatch m; regex_search(s, m, rx); s = m.suffix()) {
			string header = m[1].str();
			if(header.find('/') == string::npos)
				header = path(a).filename().string() + '/' + header;
			gr.insert_vertex(header);//if exist nullptr return
			gr.insert_vertex(b);
			gr.remove_edge(header, b);//for the case edge already exist
			gr.insert_edge(header, b, 0);
		}
	}
	for(auto *v = gr.data(); v; v = v->vertex) recur_touch(v);
}
