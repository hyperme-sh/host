#include "llama.h"
#include "nlohmann/json.hpp"
#include "counter.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
using json=nlohmann::json;
static bool permit(const char *kind,int n) {
    std::cout<<json{{"event","permit"},{"kind",kind},{"count",n}}.dump()<<std::endl;
    std::string line;if(!std::getline(std::cin,line)||line.size()>128)return false;
    auto value=json::parse(line);return value==json{{"permit",true}};
}
static void counts(const meter_counts &c) {
    std::cout<<json{{"event","counts"},{"processed_input",c.processed_input},{"accepted_output",c.accepted_output},
        {"hidden_output",c.hidden_output},{"cache_hits",c.cache_hits},{"rejected_speculative",c.rejected_speculative}}.dump()<<std::endl;
}
int main(int argc,char **argv) {
    // The guest supervisor supplies verified file descriptors, never caller paths.
    // One process/request: no cache reuse, speculative decoder, plugins or remote models.
    if(argc!=3)return 2;
    llama_log_set([](enum ggml_log_level,const char *,void *){},nullptr);
    try {
        std::string line;if(!std::getline(std::cin,line)||line.size()>65536)return 2;
        auto body=json::parse(line);
        if(!body.is_object()||body.size()!=2||!body.contains("messages")||!body.contains("max_tokens")||!body["max_tokens"].is_number_integer())return 2;
        int limit=body["max_tokens"].get<int>();if(limit<1||limit>128||!body["messages"].is_array()||body["messages"].empty()||body["messages"].size()>64)return 2;
        std::vector<std::string> roles,texts;std::vector<llama_chat_message> messages;
        for(const auto &m:body["messages"]) {
            if(!m.is_object()||m.size()!=2||!m.contains("role")||!m.contains("content")||!m["role"].is_string()||!m["content"].is_string())return 2;
            auto role=m["role"].get<std::string>();if(role!="user"&&role!="assistant"&&role!="system")return 2;
            roles.push_back(role);texts.push_back(m["content"].get<std::string>());
            if(texts.back().find('\0')!=std::string::npos)return 2;
        }
        for(size_t i=0;i<roles.size();++i)messages.push_back({roles[i].c_str(),texts[i].c_str()});
        std::ifstream template_file(argv[2]);std::string tmpl((std::istreambuf_iterator<char>(template_file)),{});
        if(tmpl.empty()||tmpl.size()>16384||tmpl.find('\0')!=std::string::npos)return 2;
        std::vector<char> prompt(131072);
        int length=llama_chat_apply_template(tmpl.c_str(),messages.data(),messages.size(),true,prompt.data(),prompt.size());
        if(length<0||size_t(length)>prompt.size())return 2;
        llama_backend_init();auto mp=llama_model_default_params();mp.n_gpu_layers=0;mp.use_mmap=false;
        auto *model=llama_model_load_from_file(argv[1],mp);if(!model)return 3;
        const auto *vocab=llama_model_get_vocab(model);
        std::vector<llama_token> tokens(2048);
        int n=llama_tokenize(vocab,prompt.data(),length,tokens.data(),tokens.size(),true,true);
        if(n<=0||n>2048)return 2;
        auto cp=llama_context_default_params();cp.n_ctx=2304;cp.n_batch=32;cp.n_ubatch=32;
        auto *ctx=llama_init_from_model(model,cp);if(!ctx)return 3;
        meter_counts c;
        for(int i=0;i<n;i+=32) {
            int size=std::min(32,n-i);if(!permit("input",size))return 4;
            c.input(size,[&]{return llama_decode(ctx,llama_batch_get_one(tokens.data()+i,size))==0;});counts(c);
        }
        for(int i=0;i<limit;++i) {
            if(!permit("output",1))return 4;
            auto *logits=llama_get_logits_ith(ctx,-1);if(!logits)return 3;
            int size=llama_vocab_n_tokens(vocab);
            llama_token token=std::max_element(logits,logits+size)-logits;
            bool end=llama_vocab_is_eog(vocab,token),hidden=end||llama_vocab_is_control(vocab,token);
            std::vector<char> piece(16384);int len=llama_token_to_piece(vocab,token,piece.data(),piece.size(),0,false);
            if(len<0||size_t(len)>piece.size())return 3;
            c.accepted(hidden||len==0);counts(c);
            if(!hidden&&len>0) {
                // Hex avoids splitting a UTF-8 code point across generated tokens.
                static const char *hex="0123456789abcdef";std::string out;
                for(int k=0;k<len;++k){unsigned char ch=piece[k];out+=hex[ch>>4];out+=hex[ch&15];}
                std::cout<<json{{"event","output"},{"hex",out}}.dump()<<std::endl;
            }
            if(end||i+1==limit)break;
            // Output work is accepted once. A failed continuation makes the exact
            // terminal state unavailable, rather than guessing a partial decode.
            if(!permit("decode",0))return 4;
            if(llama_decode(ctx,llama_batch_get_one(&token,1))!=0)return 3;
        }
        std::cout<<json{{"event","completed"}}.dump()<<std::endl;
        llama_free(ctx);llama_model_free(model);llama_backend_free();return 0;
    } catch (...) {return 3;}
}
