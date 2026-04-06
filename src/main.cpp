// src/main.cpp
// 加入「抽原始碼」功能
// cd ~/func-extractor
// cmake --build build -j
// 跑並存檔: ./build/func_extractor test.c -- -std=c11 > functions.jsonl


#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <string>
#include "clang/Lex/Lexer.h" //Lexer::getSourceText 需要


using namespace clang;
using namespace clang::tooling;
using namespace llvm;

// 設定 Command Line 參數類別
static cl::OptionCategory MyToolCategory("my-tool-options");

// ========================================================
// 1. Visitor：走訪 AST 並抓 FunctionDecl
// ========================================================

class FindFunctionsVisitor : public RecursiveASTVisitor<FindFunctionsVisitor> {
public:
    explicit FindFunctionsVisitor(ASTContext *Context) : Context(Context) {}
    //當它走到一個 "FunctionDecl" (函數宣告/定義) 時會自動呼叫此函式
    bool VisitFunctionDecl(FunctionDecl *FD){
        //只印出有實作內容 (Body) 的函數定義，忽略單純的 Header 宣告
        if(!FD) return true;
        if(!FD->hasBody()) return true; //只要「有 body」的 function（排除純宣告）

        const SourceManager &SM = Context->getSourceManager(); //包括主檔案和包含的檔案
        SourceLocation BeginLoc = FD->getBeginLoc(); //是否為無效位置
        if(BeginLoc.isInvalid()) return true;
        // 只抓 main file，避免系統 header / include 的 function 也被抓到
        if(!SM.isWrittenInMainFile(BeginLoc)) return true;

        //取得函數name
        std::string FuncName = FD->getNameInfo().getName().getAsString();

        //取得函式原始碼文字（含 signature + body）
        std::string CodeText = getFunctionSourceText(*FD, SM, Context->getLangOpts());

        //取得位置資訊
        PresumedLoc PBegin = SM.getPresumedLoc(BeginLoc);
        PresumedLoc PEnd = SM.getPresumedLoc(FD->getEndLoc());

        // 若 PresumedLoc 無效（少見），退回用 line number
        unsigned StartLine = PBegin.isValid() ? PBegin.getLine() : SM.getSpellingLineNumber(BeginLoc);
        unsigned EndLine = PEnd.isValid() ? PEnd.getLine() : SM.getSpellingLineNumber(FD->getEndLoc());
        //輸出
        // outs() << "--------------------------------------------------\n";
        // outs() << "Function:" << FuncName << "\n";
        // outs() << "Location:" << (PBegin.isValid() ? PBegin.getFilename() :"<unknown>")  //(condition ? value_if_true : value_if_false;)
        //        << ":" << StartLine << "-" << EndLine << "\n";
        // outs() << "Code Cotent:\n" << CodeText << "\n\n";

        // 改為輸出 JSONL 格式
        // 格式: {"file": "檔名", "line_start": 10, "line_end": 20, "func_name": "foo", "code": "int foo()..."}
        std::string filename = PBegin.isValid() ? std::string(PBegin.getFilename()) : "<unknown>";
        outs() << "{"
                << "\"file\" : \"" << escapeJson(filename) << "\", "
                << "\"func_name\": \"" << escapeJson(FuncName) << "\", "
                << "\"line_start\": " << StartLine << ", "
                << "\"line_end\": " << EndLine << ", "
                << "\"code\": \"" << escapeJson(CodeText) << "\"" 
                << "}\n"; // JSONL 要求每筆資料最後要換行

        return true; //繼續走訪其他 AST 節點

    }
private:
    ASTContext *Context;

    //JSON 跳脫函式
    static std::string escapeJson(const std::string &input){
        std::string output;
        output.reserve(input.size() + 16);
        auto hex = [](unsigned char x) -> char {
            return (x < 10) ? ('0' + x) : ('a' + (x - 10));
        };
        for(unsigned char c : input){
            switch (c){
                case '\"': output += "\\\""; break; // 處理雙引號
                case '\\': output += "\\\\"; break; // 處理反斜線
                case '\n': output += "\\n"; break;  // 處理換行
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;  // 處理 Tab
                case '\b': output += "\\b";  break;
                case '\f': output += "\\f";  break;
                default:
                    if (c < 0x20) {
                        output += "\\u00";
                        output += hex((c >> 4) & 0x0F);
                        output += hex(c & 0x0F);
                    } else {
                        output += static_cast<char>(c);
                    }
            }
        }
        return output;
    }
   

    // ========================================================
    // 2. 從 SourceRange 抽出原始碼文字
    // ========================================================
    static std::string getFunctionSourceText(const FunctionDecl &FD, const SourceManager &SM, const LangOptions &LO){
        //FunctionDecl 的 SourceRange 通常涵蓋 signature + body
        SourceRange SR = FD.getSourceRange();

        // getEndLoc() 指向的是最後一個 Token 的「開頭」（也就是 '}' 的左邊）。
        // 我們需要的是 '}' 的「右邊」。
        // 所以要用 CharSourceRange::getTokenRange 讓 Lexer 知道我們要包含最後那個 Token。

        CharSourceRange CSR = CharSourceRange::getTokenRange(SR);      
        bool Invalid = false;  

        // Lexer::getSourceText 是 Clang 提供的一個靜態函式，用於從指定的 CharSourceRange 中提取原始程式碼文字。
        //static StringRef getSourceText(CharSourceRange Range, const SourceManager &SM, const LangOptions &LangOpts, bool *Invalid = nullptr);            
        StringRef Text = Lexer::getSourceText(CSR, SM, LO, &Invalid); 
        
        if(Invalid) return "<Error extracting source text>";
        return Text.str(); //轉成 std::string 回傳

    }

    
};

// ========================================================
// 2. ASTConsumer: 負責接收 ASTContext 並啟動 Visitor
// ========================================================
class FindFunctionsConsumer : public ASTConsumer {
    public:
        explicit FindFunctionsConsumer(ASTContext *Context) : Visitor(Context) {}
    
        //(Translation Unit) 被 Parse 完後，會呼叫這裡
        virtual void HandleTranslationUnit(ASTContext &Context) override {
            //啟動 AST Visitor 開始走訪 AST
            Visitor.TraverseDecl(Context.getTranslationUnitDecl());
        }
    private:
        FindFunctionsVisitor Visitor;
};


//  ASTConsumer：TranslationUnit 建好後啟動 Visitor
class FindFunctionsAction : public ASTFrontendAction {
    public:
        std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) override {
            return std::make_unique<FindFunctionsConsumer>(&CI.getASTContext());
        }
    };



int main(int argc, const char **argv){
    // 解析命令列參數（LLVM 16 正確寫法）
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, MyToolCategory);
    if (!ExpectedParser) {
        errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser &OptionsParser = ExpectedParser.get();

    // 建立 ClangTool
    ClangTool Tool(
        OptionsParser.getCompilations(),
        OptionsParser.getSourcePathList()
    );

    // 5. 執行工具
    return Tool.run(newFrontendActionFactory<FindFunctionsAction>().get());
}
