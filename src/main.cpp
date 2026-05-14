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
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
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
        std::string filename = PBegin.isValid() ? std::string(PBegin.getFilename()) : "<unknown>";

        FunctionInfo Info;
        Info.file = filename;
        Info.funcName = FuncName;
        Info.lineStart = StartLine;
        Info.lineEnd = EndLine;
        Info.code = CodeText;

        CallCollector CallVisitor(Context, &Info);
        CallVisitor.TraverseStmt(FD->getBody());

        Functions.push_back(std::move(Info));

        return true; //繼續走訪其他 AST 節點

    }

    // 收集 direct call graph，輸出 caller_summary / callee_summary
    void emitJsonLines() {
        std::map<std::string, FunctionInfo *> ByName;
        for (auto &Info : Functions) {
            ByName[Info.funcName] = &Info;
        }

        std::map<std::string, std::vector<CallerEdge>> CallersByCallee;
        for (const auto &Caller : Functions) {
            std::set<std::string> SeenInCaller;
            for (const auto &Call : Caller.calls) {
                if (Call.calleeName.empty()) continue;
                std::string edgeKey = Caller.funcName + "->" + Call.calleeName;
                if (!SeenInCaller.insert(edgeKey).second) continue;

                CallerEdge Edge = buildCallerEdge(Caller, Call);
                CallersByCallee[Call.calleeName].push_back(Edge);
            }
        }

        for (const auto &Info : Functions) {
            outs() << "{"
                   << "\"file\" : \"" << escapeJson(Info.file) << "\", "
                   << "\"func_name\": \"" << escapeJson(Info.funcName) << "\", "
                   << "\"line_start\": " << Info.lineStart << ", "
                   << "\"line_end\": " << Info.lineEnd << ", "
                   << "\"caller_summary\": " << buildCallerSummaryJson(Info, CallersByCallee) << ", "
                   << "\"callee_summary\": " << buildCalleeSummaryJson(Info, ByName) << ", "
                   << "\"code\": \"" << escapeJson(Info.code) << "\""
                   << "}\n"; // JSONL 要求每筆資料最後要換行
        }
    }

private:
    struct CallInfo {
        std::string calleeName;
        std::vector<std::string> argTexts;
    };

    struct FunctionInfo {
        std::string file;
        std::string funcName;
        unsigned lineStart = 0;
        unsigned lineEnd = 0;
        std::string code;
        std::vector<CallInfo> calls;
    };

    struct CallerEdge {
        std::string funcName;
        std::string relevance;
        std::string inputOrigin;
        std::string controlPathRole;
        int relevanceScore = 0;
    };

    struct CalleeEdge {
        std::string funcName;
        std::string relevance;
        std::string roleHint;
        std::vector<std::string> dangerSignals;
        int relevanceScore = 0;
    };

    ASTContext *Context;
    std::vector<FunctionInfo> Functions;
    //  用 Clang AST CallExpr 抽 callee 與 argument expression
    class CallCollector : public RecursiveASTVisitor<CallCollector> {
    public:
        CallCollector(ASTContext *Context, FunctionInfo *Info) : Context(Context), Info(Info) {}

        bool VisitCallExpr(CallExpr *CE) {
            if (!CE || !Info) return true;

            FunctionDecl *DirectCallee = CE->getDirectCallee();
            std::string CalleeName;
            if (DirectCallee) {
                CalleeName = DirectCallee->getNameInfo().getName().getAsString();
            } else {
                CalleeName = getExprText(CE->getCallee(), Context->getSourceManager(), Context->getLangOpts());
            }
            if (CalleeName.empty()) return true;

            CallInfo Call;
            Call.calleeName = CalleeName;
            for (const Expr *Arg : CE->arguments()) {
                Call.argTexts.push_back(getExprText(Arg, Context->getSourceManager(), Context->getLangOpts()));
            }
            Info->calls.push_back(std::move(Call));
            return true;
        }

    private:
        ASTContext *Context;
        FunctionInfo *Info;
    };

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

    static std::string lowerCopy(std::string Value) {
        std::transform(Value.begin(), Value.end(), Value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return Value;
    }

    static bool containsAny(const std::string &Haystack, const std::vector<std::string> &Needles) {
        for (const auto &Needle : Needles) {
            if (Haystack.find(Needle) != std::string::npos) return true;
        }
        return false;
    }

    static std::string joinStrings(const std::vector<std::string> &Values, const std::string &Sep) {
        std::ostringstream OS;
        for (size_t I = 0; I < Values.size(); ++I) {
            if (I) OS << Sep;
            OS << Values[I];
        }
        return OS.str();
    }

    static std::vector<std::string> uniqueStrings(const std::vector<std::string> &Values) {
        std::vector<std::string> Result;
        std::set<std::string> Seen;
        for (const auto &Value : Values) {
            if (Seen.insert(Value).second) Result.push_back(Value);
        }
        return Result;
    }

    static std::string getExprText(const Expr *E, const SourceManager &SM, const LangOptions &LO) {
        if (!E) return "";
        CharSourceRange CSR = CharSourceRange::getTokenRange(E->getSourceRange());
        bool Invalid = false;
        StringRef Text = Lexer::getSourceText(CSR, SM, LO, &Invalid);
        if (Invalid) return "";
        return Text.str();
    }

    static std::string classifyInputOrigin(const std::vector<std::string> &ArgTexts) {
        std::string Combined = lowerCopy(joinStrings(ArgTexts, " "));
        if (containsAny(Combined, {"request", "req", "http", "uri", "header", "body", "socket", "recv", "read", "packet", "buf", "buffer", "data", "input", "chunk"})) {
            return "likely external input";
        }
        if (containsAny(Combined, {"parser", "parse", "token", "cursor", "offset", "pos", "len", "length", "size", "tag", "action", "field", "state"})) {
            return "parser path or derived parser state";
        }
        if (containsAny(Combined, {"argv", "env", "user", "file", "path", "stdin", "malicious", "tainted"})) {
            return "likely user-controlled data";
        }
        if (ArgTexts.empty()) return "no call arguments";
        return "unclear from call arguments";
    }

    static std::string summarizeCallerRelevance(const std::vector<std::string> &ArgTexts, const std::string &InputOrigin) {
        std::string Combined = lowerCopy(joinStrings(ArgTexts, " "));
        std::vector<std::string> Details;
        if (containsAny(Combined, {"buf", "buffer", "data", "ptr", "pointer"})) Details.push_back("buffer/pointer argument");
        if (containsAny(Combined, {"len", "length", "size", "count", "max", "remain", "remaining"})) Details.push_back("length/size argument");
        if (containsAny(Combined, {"off", "offset", "pos", "position", "cursor", "idx", "index"})) Details.push_back("offset/progress argument");
        if (containsAny(Combined, {"state", "ctx", "context", "parser"})) Details.push_back("state/context argument");
        if (containsAny(Combined, {"argv", "env", "user", "request", "input", "file", "packet", "chunk"})) Details.push_back("externally influenced argument");

        if (Details.empty()) {
            return "calls current function; argument source is not obvious from syntax";
        }
        return "passes " + joinStrings(uniqueStrings(Details), ", ") + " into current function";
    }

    static bool callerNameLooksRelevant(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {"parser", "parse", "read", "decode", "load", "handle", "process", "scan", "check", "validate", "dispatch", "main"});
    }

    static bool callerLooksLikeExternalEntry(const FunctionInfo &Caller) {
        std::string NameAndCode = lowerCopy(Caller.funcName + " " + Caller.code);
        return containsAny(NameAndCode, {
            "main", "argv", "argc", "stdin", "fread", "read(", "recv", "socket",
            "request", "http", "uri", "file", "input", "load", "parse"
        });
    }

    static int scoreCallerRelevance(const FunctionInfo &Caller, const CallInfo &Call, const std::string &InputOrigin) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        int Score = 0;
        if (containsAny(Args, {"buf", "buffer", "data", "ptr", "pointer"})) Score += 3;
        if (containsAny(Args, {"len", "length", "size", "count", "max", "remain", "remaining"})) Score += 3;
        if (containsAny(Args, {"off", "offset", "pos", "position", "cursor", "idx", "index"})) Score += 3;
        if (containsAny(Args, {"state", "ctx", "context", "parser"})) Score += 3;
        if (callerNameLooksRelevant(Caller.funcName)) Score += 2;
        if (callerLooksLikeExternalEntry(Caller)) Score += 2;
        if (InputOrigin == "likely external input" || InputOrigin == "likely user-controlled data") Score += 2;
        if (InputOrigin == "parser path or derived parser state") Score += 1;
        return Score;
    }

    static std::string summarizeControlPathRole(const FunctionInfo &Caller, const CallInfo &Call, int RelevanceScore) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        if (callerLooksLikeExternalEntry(Caller)) {
            return "close to an external-input entry or parser entry path";
        }
        if (callerNameLooksRelevant(Caller.funcName) || containsAny(Args, {"state", "ctx", "parser", "offset", "cursor", "len", "length"})) {
            return "on the upstream parser/control path";
        }
        if (RelevanceScore >= 4) {
            return "receiving security-relevant data from its caller";
        }
        return "connected by a direct call, but control-path importance is unclear";
    }

    static CallerEdge buildCallerEdge(const FunctionInfo &Caller, const CallInfo &Call) {
        CallerEdge Edge;
        Edge.funcName = Caller.funcName;
        Edge.inputOrigin = classifyInputOrigin(Call.argTexts);
        Edge.relevance = summarizeCallerRelevance(Call.argTexts, Edge.inputOrigin);
        Edge.relevanceScore = scoreCallerRelevance(Caller, Call, Edge.inputOrigin);
        Edge.controlPathRole = summarizeControlPathRole(Caller, Call, Edge.relevanceScore);
        return Edge;
    }

    // 針對被呼叫者（Callee）的分析。它會掃描被呼叫函數的名字和原始碼，尋找危險特徵：
    static std::vector<std::string> detectDangerSignals(const std::string &FuncName, const std::string &Code) {
        std::string Text = lowerCopy(FuncName + " " + Code);
        std::vector<std::string> Signals;
        if (containsAny(Text, {"memcpy", "memmove", "bcopy", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf", "copy"})) {
            Signals.push_back("memory copy");
        }
        if (containsAny(Text, {"strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp", "strncmp", "snprintf", "sprintf", "strchr", "strstr"})) {
            Signals.push_back("string handling");
        }
        if (containsAny(Text, {"memcpy", "memmove", "strncpy", "strncat", "snprintf", "sprintf", "len", "length", "size", "count", "nbytes"})) {
            Signals.push_back("length-dependent operation");
        }
        if (containsAny(Text, {"malloc", "calloc", "realloc", "alloc", "new "})) Signals.push_back("allocation");
        if (containsAny(Text, {"push", "pop", "stack", "stackptr", "stack_ptr", "top", "peek"})) Signals.push_back("stack manipulation");
        if (containsAny(Text, {"len", "length", "size", "remain", "remaining", "consumed", "chunk_size", "content_length", "nread", "read_bytes"})) Signals.push_back("length/remaining/consumed update");
        if (containsAny(Text, {"state", "status", "mode", "phase", "switch", "case"})) Signals.push_back("parser state update");
        if (containsAny(Text, {"*p", "->data", "write", "put", "append", "emit", "dst", "dest", "sprintf", "snprintf", "strcpy", "strncpy", "memcpy", "memmove"})) Signals.push_back("buffer write");
        if (containsAny(Text, {"pos", "cursor", "offset", "advance", "next", "consume", "read", "p++", "++p"})) Signals.push_back("parser progress update");
        if (containsAny(Text, {"cast", "static_cast", "reinterpret_cast", "(int)", "(char", "(unsigned", "(size_t", "(uint", "(long", "(short", "type", "enum"})) Signals.push_back("type conversion/cast");
        if (containsAny(Text, {"valid", "validate", "check", "assert", "return 0", "return 1", "error", "invalid", "reject"})) Signals.push_back("validation logic");
        return uniqueStrings(Signals);
    }

    static std::string summarizeCalleeRelevance(const std::vector<std::string> &Signals) {
        if (Signals.empty()) return "has no obvious MVP danger signal";
        return "performs " + joinStrings(Signals, ", ");
    }

    static std::string summarizeCalleeRoleHint(const std::vector<std::string> &Signals) {
        std::string SignalText = joinStrings(Signals, " ");
        if (containsAny(SignalText, {"validation logic", "parser state update", "type conversion/cast"})) {
            return "downstream validation/state helper";
        }
        if (containsAny(SignalText, {"memory copy", "allocation", "buffer write", "string handling", "stack manipulation"})) {
            return "downstream dangerous primitive helper";
        }
        return "direct helper";
    }

    static int scoreCalleeRelevance(const std::vector<std::string> &Signals) {
        int Score = 0;
        for (const auto &Signal : Signals) {
            if (Signal == "memory copy" || Signal == "buffer write") Score += 4;
            else if (Signal == "allocation" || Signal == "string handling" || Signal == "stack manipulation") Score += 3;
            else if (Signal == "parser state update" || Signal == "length/remaining/consumed update" || Signal == "parser progress update") Score += 3;
            else if (Signal == "type conversion/cast" || Signal == "validation logic" || Signal == "length-dependent operation") Score += 2;
            else Score += 1;
        }
        return Score;
    }

    static CalleeEdge buildCalleeEdge(const CallInfo &Call, const std::map<std::string, FunctionInfo *> &ByName) {
        auto It = ByName.find(Call.calleeName);
        std::string CalleeCode = (It != ByName.end()) ? It->second->code : "";
        std::vector<std::string> Signals = detectDangerSignals(Call.calleeName, CalleeCode);

        CalleeEdge Edge;
        Edge.funcName = Call.calleeName;
        Edge.dangerSignals = Signals;
        Edge.relevance = summarizeCalleeRelevance(Signals);
        Edge.roleHint = summarizeCalleeRoleHint(Signals);
        Edge.relevanceScore = scoreCalleeRelevance(Signals);
        return Edge;
    }

    static std::vector<CalleeEdge> selectTopCallees(const std::vector<CalleeEdge> &Edges) {
        std::vector<CalleeEdge> Ranked;
        for (const auto &Edge : Edges) {
            if (Edge.relevanceScore > 0) Ranked.push_back(Edge);
        }
        std::stable_sort(Ranked.begin(), Ranked.end(), [](const CalleeEdge &A, const CalleeEdge &B) {
            return A.relevanceScore > B.relevanceScore;
        });
        if (Ranked.size() > 2) Ranked.resize(2);
        return Ranked;
    }

    static std::vector<std::string> buildCalleeSummaryLines(const std::vector<CalleeEdge> &TopEdges) {
        std::vector<std::string> Lines;
        if (TopEdges.empty()) {
            Lines.push_back("No risk-relevant direct callee was selected for this function.");
            Lines.push_back("No downstream helper risk is visible from direct calls.");
            return Lines;
        }

        const CalleeEdge &Top = TopEdges.front();
        Lines.push_back("Top callee: " + Top.funcName + " (" + Top.roleHint + "); relevance: " + Top.relevance + ".");
        if (TopEdges.size() > 1) {
            std::vector<std::string> OtherNames;
            for (size_t I = 1; I < TopEdges.size(); ++I) OtherNames.push_back(TopEdges[I].funcName);
            Lines.push_back("Other selected callee: " + joinStrings(OtherNames, ", ") + ".");
        }
        if (!Top.dangerSignals.empty()) {
            Lines.push_back("Downstream risk signals: " + joinStrings(Top.dangerSignals, ", ") + ".");
        } else {
            Lines.push_back("No obvious dangerous downstream primitive was detected in the top callee.");
        }
        return Lines;
    }

    static std::string buildJsonStringArray(const std::vector<std::string> &Values) {
        std::ostringstream OS;
        OS << "[";
        for (size_t I = 0; I < Values.size(); ++I) {
            if (I) OS << ", ";
            OS << "\"" << escapeJson(Values[I]) << "\"";
        }
        OS << "]";
        return OS.str();
    }

    static std::vector<CallerEdge> selectTopCallers(const std::vector<CallerEdge> &Edges) {
        std::vector<CallerEdge> Ranked = Edges;
        std::stable_sort(Ranked.begin(), Ranked.end(), [](const CallerEdge &A, const CallerEdge &B) {
            return A.relevanceScore > B.relevanceScore;
        });
        if (Ranked.size() > 2) Ranked.resize(2);
        return Ranked;
    }

    static std::string buildCallerSummaryLine(const std::vector<CallerEdge> &TopEdges) {
        if (TopEdges.empty()) return "No direct caller was found for this function in the current translation unit.";

        const CallerEdge &Top = TopEdges.front();
        std::string Line = "Top caller: " + Top.funcName + " (" + Top.controlPathRole + "); relevance: " + Top.relevance + ".";
        if (TopEdges.size() > 1) {
            std::vector<std::string> OtherNames;
            for (size_t I = 1; I < TopEdges.size(); ++I) OtherNames.push_back(TopEdges[I].funcName);
            Line += " Other selected caller: " + joinStrings(OtherNames, ", ") + ".";
        }
        return Line;
    }

    static std::vector<std::string> buildCallerSummaryLines(const std::vector<CallerEdge> &TopEdges) {
        std::vector<std::string> Lines;
        Lines.push_back(buildCallerSummaryLine(TopEdges));

        if (TopEdges.empty()) {
            Lines.push_back("Input origin is unclear from direct caller context.");
            Lines.push_back("Current function may be an entry point or may be called outside the current translation unit.");
            return Lines;
        }

        const CallerEdge &Top = TopEdges.front();
        if (Top.inputOrigin == "unclear from call arguments" || Top.inputOrigin == "no call arguments") {
            Lines.push_back("Input origin is unclear from direct call arguments.");
        } else {
            Lines.push_back("Input origin: " + Top.inputOrigin + ".");
        }
        Lines.push_back("Caller question: this function appears reachable through " + Top.controlPathRole + ".");
        return Lines;
    }

    static std::string buildCallerSummaryJson(
        const FunctionInfo &Info,
        const std::map<std::string, std::vector<CallerEdge>> &CallersByCallee
    ) {
        auto It = CallersByCallee.find(Info.funcName);
        std::vector<CallerEdge> AllEdges = (It != CallersByCallee.end()) ? It->second : std::vector<CallerEdge>{};
        std::vector<CallerEdge> TopEdges = selectTopCallers(AllEdges);
        std::vector<std::string> SummaryLines = buildCallerSummaryLines(TopEdges);

        std::ostringstream OS;
        OS << "{\"num_callers\": " << AllEdges.size()
           << ", \"summary_lines\": " << buildJsonStringArray(SummaryLines)
           << ", \"callers\": [";
        for (size_t I = 0; I < TopEdges.size(); ++I) {
            if (I) OS << ", ";
            OS << "{"
               << "\"func_name\": \"" << escapeJson(TopEdges[I].funcName) << "\", "
               << "\"role_hint\": \"" << escapeJson(TopEdges[I].controlPathRole) << "\", "
               << "\"relevance\": \"" << escapeJson(TopEdges[I].relevance) << "\", "
               << "\"input_hint\": \"" << escapeJson(TopEdges[I].inputOrigin) << "\", "
               << "\"relevance_score\": " << TopEdges[I].relevanceScore
               << "}";
        }
        OS << "]}";
        return OS.str();
    }

    static std::string buildCalleeSummaryJson(const FunctionInfo &Info, const std::map<std::string, FunctionInfo *> &ByName) {
        std::vector<CallInfo> UniqueCalls;
        std::set<std::string> Seen;
        for (const auto &Call : Info.calls) {
            if (Seen.insert(Call.calleeName).second) UniqueCalls.push_back(Call);
        }

        std::vector<CalleeEdge> AllEdges;
        for (const auto &Call : UniqueCalls) {
            AllEdges.push_back(buildCalleeEdge(Call, ByName));
        }
        std::vector<CalleeEdge> TopEdges = selectTopCallees(AllEdges);
        std::vector<std::string> SummaryLines = buildCalleeSummaryLines(TopEdges);

        std::ostringstream OS;
        OS << "{\"num_callees\": " << UniqueCalls.size()
           << ", \"summary_lines\": " << buildJsonStringArray(SummaryLines)
           << ", \"callees\": [";
        for (size_t I = 0; I < TopEdges.size(); ++I) {
            if (I) OS << ", ";
            OS << "{"
               << "\"func_name\": \"" << escapeJson(TopEdges[I].funcName) << "\", "
               << "\"role_hint\": \"" << escapeJson(TopEdges[I].roleHint) << "\", "
               << "\"relevance\": \"" << escapeJson(TopEdges[I].relevance) << "\", "
               << "\"danger_hint\": " << buildJsonStringArray(TopEdges[I].dangerSignals) << ", "
               << "\"relevance_score\": " << TopEdges[I].relevanceScore
               << "}";
        }
        OS << "]}";
        return OS.str();
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
            Visitor.emitJsonLines();
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
