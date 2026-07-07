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
// 3. Visitor：走訪 AST 並抓 FunctionDecl
// ========================================================

/*
FindFunctionsConsumer::HandleTranslationUnit()
  -> Visitor.TraverseDecl(Context.getTranslationUnitDecl())
      -> VisitFunctionDecl()
          -> 過濾 function
          -> 抽 function name / file / line / code
          -> CallCollector.TraverseStmt(Body)
              -> 收集 CallExpr
              -> 偵測 BinaryOperator direct evidence
          -> addSecurityOrderingSignals()
          -> Functions.push_back(Info)

  -> Visitor.emitJsonLines()
      -> 建立 caller/callee 關聯
      -> 產生 JSONL
*/

/*
FindFunctionsVisitor 主要做 5 件事:
1. 找出 main file 裡所有有 body 的 function definition
2. 抽出每個 function 的原始碼與行號
3. 收集每個 function 裡呼叫了哪些 callee
4. 分析 caller / callee 的關聯與安全相關 signals
5. 輸出每個 function 一行 JSONL
*/

class FindFunctionsVisitor : public RecursiveASTVisitor<FindFunctionsVisitor> {
public:
    explicit FindFunctionsVisitor(ASTContext *Context) : Context(Context) {}
    //當它走到一個 "FunctionDecl" (函數宣告/定義) 時會自動呼叫此函式
    bool VisitFunctionDecl(FunctionDecl *FD){
        // 只印出有實作內容 (Body) 的函數定義，忽略單純的 Header 宣告
        // 過濾不需要的 function
        if(!FD) return true;
        if(!FD->isThisDeclarationADefinition()) return true; // 排除 forward declaration/redeclaration
        Stmt *Body = FD->getBody();
        if(!Body) return true; //只要「有 body」的 function（排除純宣告）

        /*
        物件              | 意思                                  
        ---------------- | -------------------------------       
        `SourceManager`  | 管理 source file、line number、檔案位置  (clang的地圖)
        `SourceLocation` | 某段程式碼在 source 裡的位置             
        `BeginLoc`       | function 開始的位置                    
        */
        const SourceManager &SM = Context->getSourceManager(); //包括主檔案和包含的檔案
        SourceLocation BeginLoc = FD->getBeginLoc(); //BeginLoc 指向 function signature 的第一個 token。
        if(BeginLoc.isInvalid()) return true; //是否為無效位置
        if(!SM.isWrittenInMainFile(BeginLoc)) return true;  // 只抓 main file，避免系統 header / include 的 function 也被抓到

        /*抽出 function metadata: function name, function source code, file name, start line, end line*/
        std::string FuncName = FD->getNameInfo().getName().getAsString(); //取得函數name
        std::string CodeText = getFunctionSourceText(*FD, SM, Context->getLangOpts());  //取得函式原始碼文字（含 signature + body）
        
        //取得位置資訊
        PresumedLoc PBegin = SM.getPresumedLoc(BeginLoc);
        PresumedLoc PEnd = SM.getPresumedLoc(FD->getEndLoc());
        
        // 若 PresumedLoc 無效（少見），退回用 line number
        unsigned StartLine = PBegin.isValid() ? PBegin.getLine() : SM.getSpellingLineNumber(BeginLoc);
        unsigned EndLine = PEnd.isValid() ? PEnd.getLine() : SM.getSpellingLineNumber(FD->getEndLoc());
        std::string filename = PBegin.isValid() ? std::string(PBegin.getFilename()) : "<unknown>";
        
        // 把剛剛抽到的東西裝進 FunctionInfo
        FunctionInfo Info;
        Info.file = filename;
        Info.funcName = FuncName;
        Info.lineStart = StartLine;
        Info.lineEnd = EndLine;
        Info.code = CodeText;

        /* CallCollector 負責單一 function body：找這個 function 裡呼叫了哪些 callee */
        CallCollector CallVisitor(Context, &Info);
        CallVisitor.TraverseStmt(Body);
        addSecurityOrderingSignals(Info); // 補上currentFunctionSignals和crossFunctionDirectEvidence
        Functions.push_back(std::move(Info));

        return true; //繼續走訪其他 AST 節點

    }

    // 收集 direct call graph，輸出 caller_summary / callee_summary
    void emitJsonLines() {
        // 建立 function name 查找表: function name -> FunctionInfo*
        std::map<std::string, FunctionInfo *> ByName;
        for (auto &Info : Functions) {
            ByName[Info.funcName] = &Info;
        }

        /* 建立反向 caller 表: callee name -> 哪些 function 呼叫它 */
        std::map<std::string, std::vector<CallerEdge>> CallersByCallee;
        for (const auto &Caller : Functions) {
            std::set<std::string> SeenInCaller; // 為了避免同一個 caller 對同一個 callee 重複計算
            for (const auto &Call : Caller.calls) {
                if (Call.calleeName.empty()) continue;
                std::string edgeKey = Caller.funcName + "->" + Call.calleeName;
                if (!SeenInCaller.insert(edgeKey).second) continue;

                CallerEdge Edge = buildCallerEdge(Caller, Call);
                CallersByCallee[Call.calleeName].push_back(Edge); //建立反向表
            }
        }

        for (const auto &Info : Functions) {
            // JSONL requires each complete JSON object to occupy exactly one line.
            outs() << "{"
                   << "\"file\":\"" << escapeJson(Info.file) << "\","
                   << "\"func_name\":\"" << escapeJson(Info.funcName) << "\","
                   << "\"line_start\":" << Info.lineStart << ","
                   << "\"line_end\":" << Info.lineEnd << ","
                   << "\"caller_summary\":" << buildCallerSummaryJson(Info, CallersByCallee) << ","
                   << "\"callee_summary\":" << buildCalleeSummaryJson(Info, ByName) << ","
                   << "\"current_function_signals\":" << buildJsonStringArray(Info.currentFunctionSignals) << ","
                   << "\"cross_function_direct_evidence\":"
                   << buildCrossFunctionDirectEvidenceJson(Info.crossFunctionDirectEvidence) << ","
                   << "\"code\":\"" << escapeJson(Info.code) << "\""
                   << "}\n";
        }
    }

/* FindFunctionsVisitor 裡面的內部資料模型 */
private:
    struct CallInfo {
        std::string calleeName;
        std::vector<std::string> argTexts;
    };

    struct DirectEvidence {
        std::string kind;
        std::string lhs;
        std::string calleeName;
        std::string expression;
        std::string evidenceStrength;
        std::string explanation;
        bool boundCheckObserved = false;
    };

    struct FunctionInfo {
        std::string file;
        std::string funcName;
        unsigned lineStart = 0;
        unsigned lineEnd = 0;
        std::string code;
        std::vector<CallInfo> calls;
        std::vector<std::string> currentFunctionSignals;
        std::vector<DirectEvidence> crossFunctionDirectEvidence;
    };

    struct CallerEdge {
        std::string funcName;
        std::string relevance;
        std::string inputOrigin;
        std::string inputPathHint;
        std::string controlPathRole;
        std::vector<std::string> argTexts;
        std::vector<std::string> argumentCategories;
        std::string relationKind = "direct_caller";
        int relevanceScore = 0;
    };

    struct OperationSignal {
        std::string operationClass;
        std::string cweFamily;
        std::string evidence;
    };

    struct CalleeEdge {
        std::string funcName;
        std::string relevance;
        std::string roleHint;
        std::vector<std::string> argTexts;
        std::vector<std::string> argumentCategories;
        std::vector<std::string> dangerSignals;
        std::vector<std::string> localSignals;
         // New taxonomy-guided fields
        std::vector<OperationSignal> operationSignals;
        std::vector<std::string> operationClasses;
        std::vector<std::string> cweFamilies;

        std::string evidenceScope = "downstream_only";
        bool isCurrentFunctionEvidence = false;
        bool isDownstreamEvidence = true;
        int argumentFlowScore = 0; //傳入參數是否像 buffer、length、path、uid、auth policy 等重要資料
        int roleMatchScore = 0; // callee 的角色是否和參數類型吻合，例如傳 buffer 給 memory helper
        int dangerSignalScore = 0; // ecallee 本身是否有 memory copy、buffer write、parser update 等 signal
        // New taxonomy-guided scores
        int operationSignalScore = 0; // callee 是否有 taxonomy operation，例如 command execution、privilege transition
        int securityContextScore = 0; // 名稱/code 是否涉及 auth、policy、root、crypto 等安全上下文

        int relevanceScore = 0; // 綜合分數，用來排序 top callees
        
        
    };

    ASTContext *Context; // clang ASTContext，提供 AST 節點的上下文資訊
    std::vector<FunctionInfo> Functions; // 存放目前 translation unit 中所有被收集到的 function 資訊

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

    /* 將字串轉換為小寫並返回副本 */
    static std::string lowerCopy(std::string Value) {
        std::transform(Value.begin(), Value.end(), Value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return Value;
    }

    /* 檢查字串是否包含任何指定的子字串 */
    static bool containsAny(const std::string &Haystack, const std::vector<std::string> &Needles) {
        for (const auto &Needle : Needles) {
            if (Haystack.find(Needle) != std::string::npos) return true;
        }
        return false;
    }
    /* 把 vector<string> 串成一個字串 */
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

    /* 把 Clang AST 裡的一個 expression 節點，轉回「原始碼文字」的 helper function */
    static std::string getExprText(const Expr *E, const SourceManager &SM, const LangOptions &LO) {
        if (!E) return "";
        CharSourceRange CSR = CharSourceRange::getTokenRange(E->getSourceRange());
        bool Invalid = false;
        StringRef Text = Lexer::getSourceText(CSR, SM, LO, &Invalid);
        if (Invalid) return "";
        return Text.str();
    }

    // ========================================================
    // 從 SourceRange 抽出原始碼文字
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
    //  CallCollector 是一個專門走訪某個 function body 的小型 AST visitor。
    /* 在目前 function 裡找出所有 function call，記錄「呼叫了誰」以及「傳了哪些參數」。
        找到一個 function
            -> 建立 FunctionInfo Info
            -> 用 CallCollector 掃描這個 function 的 body
            -> 把 body 裡的 function calls 存進 Info.calls
    */
    class CallCollector : public RecursiveASTVisitor<CallCollector> {
    public:
        /* CallCollector 是用來掃描單一 function body 的 visitor */
        CallCollector(ASTContext *Context, FunctionInfo *Info) : Context(Context), Info(Info) {}

        /*VisitCallExpr() 會抓每個 function call 的 callee 名稱與 argument 原始碼，存進目前 FunctionInfo.calls*/
        // VisitCallExpr 會在 AST 裡遇到 CallExpr 節點時被呼叫，這裡負責收集 callee name 和參數文字。
        bool VisitCallExpr(CallExpr *CE) {
            if (!CE || !Info) return true;

            // 取得 callee 名稱 
            FunctionDecl *DirectCallee = CE->getDirectCallee();
            std::string CalleeName;
            if (DirectCallee) {
                CalleeName = DirectCallee->getNameInfo().getName().getAsString();
            } else {
                // 能用 AST 找到明確 function name 就用 AST；找不到就退回 source text。
                CalleeName = getExprText(CE->getCallee(), Context->getSourceManager(), Context->getLangOpts());
            }
            if (CalleeName.empty()) return true;

            CallInfo Call;
            Call.calleeName = CalleeName;
            // 逐一處理 call 的每個 argument，這些 argument 之後會拿去分類
            for (const Expr *Arg : CE->arguments()) {
                Call.argTexts.push_back(getExprText(Arg, Context->getSourceManager(), Context->getLangOpts()));
            }
            Info->calls.push_back(std::move(Call));
            return true;
        }

        /* 用來偵測「目前 function 的 progress/index/loop 變數是否由 callee 回傳值更新」。
        如果有，它會加入 currentFunctionSignals 和 crossFunctionDirectEvidence，表示這是一個跨函式互動造成、但應該歸因於目前 function 的直接安全據。 */
        // 會檢查 assignment 是否使用 call return來更新 loop/index 變數，這是 parser 進度控制的 strong signal。
        bool VisitBinaryOperator(BinaryOperator *BO) {
            if (!BO || !Info) return true;
            std::string LHS = getExprText(BO->getLHS(), Context->getSourceManager(), Context->getLangOpts());
            std::string RHS = getExprText(BO->getRHS(), Context->getSourceManager(), Context->getLangOpts());
            if (!assignmentUsesCallReturn(BO, LHS, RHS)) return true; // 如果不是「用 callee 回傳值更新 loop/index 變數」，就跳過

            std::string Op = BO->getOpcodeStr().str();
            if (LHS.empty() || RHS.empty()) return true;

            std::string CalleeName = getFirstCalleeName(BO->getRHS(), Context);
            std::string Expression = LHS + " " + Op + " " + RHS;
            std::string Signal = "unchecked callee return controls loop progress: " + Expression;
            Info->currentFunctionSignals.push_back(Signal);
            Info->currentFunctionSignals = uniqueStrings(Info->currentFunctionSignals);

            //它不是一般的「callee 有危險操作」；它想標出 跨函式互動造成的 current-function direct evidence。
            DirectEvidence Evidence;
            Evidence.kind = "unchecked_callee_return_controls_loop_progress";
            Evidence.lhs = LHS;
            Evidence.calleeName = CalleeName.empty() ? "unknown" : CalleeName;
            Evidence.expression = Expression;
            Evidence.evidenceStrength = "strong";
            Evidence.explanation =
                "The current function updates its own loop/index/progress variable using a callee return value without an observed local bounds/progress check. "
                "This is direct evidence for the current function because parser traversal/progress control occurs in the current function body.";
            Evidence.boundCheckObserved = false;

            // 避免重複加入相同的 direct evidence
            bool Seen = false;
            for (const auto &Existing : Info->crossFunctionDirectEvidence) {
                if (Existing.kind == Evidence.kind && Existing.expression == Evidence.expression) {
                    Seen = true;
                    break;
                }
            }
            if (!Seen) Info->crossFunctionDirectEvidence.push_back(Evidence);
            return true;
        }

    private:
        ASTContext *Context;
        FunctionInfo *Info;
        /* 判斷某個 AST subtree 裡面有沒有 function call。 */
        class CallPresenceVisitor : public RecursiveASTVisitor<CallPresenceVisitor> {
        public:
            bool found = false;

            bool VisitCallExpr(CallExpr *CE) {
                if (CE) found = true;
                return false;
            }
        };

        /* 判斷 RHS 裡有沒有 call: 它會遞迴掃描某個 AST subtree */
        static bool subtreeContainsCall(Stmt *S) {
            if (!S) return false;
            CallPresenceVisitor Visitor;
            Visitor.TraverseStmt(S);
            return Visitor.found;
        }
        
        /* FirstCallNameVisitor 用來從某段 AST 裡抓第一個 function call 的 callee 名稱；
        能解析 direct callee 就用 Clang 的 FunctionDecl，不能解析就退回原始碼文字。 */
        class FirstCallNameVisitor : public RecursiveASTVisitor<FirstCallNameVisitor> {
        public:
            explicit FirstCallNameVisitor(ASTContext *Context) : Context(Context) {}

            bool VisitCallExpr(CallExpr *CE) {
                if (!CE || !calleeName.empty()) return false;

                if (FunctionDecl *FD = CE->getDirectCallee()) {
                    calleeName = FD->getNameInfo().getName().getAsString();
                } else if (Context) {
                    calleeName = getExprText(CE->getCallee(), Context->getSourceManager(), Context->getLangOpts());
                }
                return false;
            }

            std::string calleeName;

        private:
            ASTContext *Context;
        };

        /* 把使用 FirstCallNameVisitor 的步驟包起來:
        getFirstCalleeName(RHS, Context)
            -> 建立 FirstCallNameVisitor
            -> TraverseStmt(RHS)
            -> VisitCallExpr(parse_next(buf))
            -> calleeName = "parse_next"
            -> return "parse_next"
        */
        static std::string getFirstCalleeName(Stmt *S, ASTContext *Context) {
            if (!S || !Context) return "";
            FirstCallNameVisitor Visitor(Context);
            Visitor.TraverseStmt(S);
            return Visitor.calleeName;
        }

        /* 判斷 LHS 是否像 progress/index/loop 變數 */
        static bool looksLikeProgressVariable(const std::string &LHS, const std::string &RHS) {
            std::string Name = lowerCopy(LHS);
            std::string Right = lowerCopy(RHS);
            if (containsAny(Name, {"cursor", "pos", "position", "idx", "index", "offset", "off", "read", "consume", "consumed", "remain", "remaining", "progress", "nread"})) {
                return true;
            }
            if ((Name == "i" || Name == "j" || Name == "k" || Name == "n") && Right.find(Name) != std::string::npos) {
                return true;
            }
            return false;
        }

        /* 判斷賦值語句是否使用了函數調用的返回值 */
        static bool assignmentUsesCallReturn(BinaryOperator *BO, const std::string &LHS, const std::string &RHS) {
            if (!BO) return false;
            //第一條：+= 或 -=
            BinaryOperatorKind Opcode = BO->getOpcode();
            if (Opcode == BO_AddAssign || Opcode == BO_SubAssign) {
                return subtreeContainsCall(BO->getRHS()); // RHS 裡必須有 function call
            }
            //第二條：=
            return Opcode == BO_Assign
                && subtreeContainsCall(BO->getRHS())
                && looksLikeProgressVariable(LHS, RHS); // LHS 必須像 progress/index/loop 變數
        }
    };

    /* 判斷某個 callee 名稱像不像「安全邊界轉換」 */
    static bool callNameLooksBoundaryTransition(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {
            "pivot_root", "unpivot", "chroot", "runchroot", "setns", "mount",
            "chdir", "fchdir", "setuid", "seteuid", "setreuid", "setresuid",
            "setgid", "setegid", "setregid", "setresgid", "setgroups",
            "initgroups", "set_perms", "restore_perms", "capset"
        });
    }

    /* 判斷某個 callee 名稱像不像「權限依賴解析」 */
    static bool callNameLooksAuthorityDependentResolution(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {
            "resolve", "resolve_cmnd", "find_path", "find_editor", "lookup",
            "getpwnam", "getpwuid", "getgrnam", "getgrgid", "sudo_getpw",
            "sudo_getgr", "nss", "realpath", "canonical", "open_conf_path",
            "open", "stat", "lstat", "fstat", "readlink", "sudo_secure"
        });
    }

    /* 這組程式是在同一個 function 的 call sequence 裡，找「安全邊界轉換」後面是否接著出現「受權限/路徑/身份狀態影響的解析操作」。
    如果有，就把這個呼叫順序標成目前 function 的直接安全證據。 */
    static void addSecurityOrderingSignals(FunctionInfo &Info) {
        for (size_t I = 0; I < Info.calls.size(); ++I) {
            const CallInfo &BoundaryCall = Info.calls[I];
            if (!callNameLooksBoundaryTransition(BoundaryCall.calleeName)) continue;

            for (size_t J = I + 1; J < Info.calls.size(); ++J) {
                const CallInfo &ResolutionCall = Info.calls[J];
                if (!callNameLooksAuthorityDependentResolution(ResolutionCall.calleeName)) continue;

                std::string Expression = BoundaryCall.calleeName + " -> " + ResolutionCall.calleeName;
                std::string Signal =
                    "security-sensitive boundary transition around authority-dependent resolution: " +
                    Expression;
                Info.currentFunctionSignals.push_back(Signal);
                Info.currentFunctionSignals = uniqueStrings(Info.currentFunctionSignals);
                
                /* 目前 function 先改變安全邊界狀態，然後做 path/name/command/authority-dependent resolution。
                這個順序本身就是目前 function 的直接證據。 */
                DirectEvidence Evidence;
                Evidence.kind = "security_boundary_transition_around_resolution";
                Evidence.lhs = "security boundary state";
                Evidence.calleeName = ResolutionCall.calleeName;
                Evidence.expression = Expression;
                Evidence.evidenceStrength = "strong";
                Evidence.explanation =
                    "The current function locally performs a security-sensitive boundary transition before or around "
                    "name, path, command, or authority-dependent resolution. Treat this ordering as direct current-function "
                    "evidence because the security boundary state controls how the later lookup is interpreted.";
                Evidence.boundCheckObserved = false;

                bool Seen = false;
                for (const auto &Existing : Info.crossFunctionDirectEvidence) {
                    // 如果同樣的 evidence 已經存在，就不重複加入。 
                    if (Existing.kind == Evidence.kind && Existing.expression == Evidence.expression) {
                        Seen = true;
                        break;
                    }
                }
                if (!Seen) Info.crossFunctionDirectEvidence.push_back(Evidence);
                break;
            }
        }
    }

    /* 根據 call arguments 的字面名稱，猜測這些資料來源像不像外部輸入、parser 狀態、user/file 來源 */
    static std::string classifyInputOrigin(const std::vector<std::string> &ArgTexts) {
        std::string Combined = lowerCopy(joinStrings(ArgTexts, " "));
        if (containsAny(Combined, {"request", "req", "http", "uri", "header", "body", "socket", "recv", "read", "packet", "buf", "buffer", "data", "input", "chunk"})) {
            return "syntactic input-like argument";
        }
        if (containsAny(Combined, {"parser", "parse", "token", "cursor", "offset", "pos", "len", "length", "size", "tag", "action", "field", "state"})) {
            return "parser path or derived parser state";
        }
        if (containsAny(Combined, {"argv", "env", "user", "file", "path", "stdin", "malicious", "tainted"})) {
            return "syntactic user/file-like argument";
        }
        if (ArgTexts.empty()) return "no call arguments";
        return "unclear from call arguments";
    }

    /* 把 classifyInputOrigin() 的結果轉成比較中性、適合輸出的描述。對於LLM判斷時候叫敏感 */
    //將classifyInputOrigin的結果再中和成一個更 general 的 hint，這是對 control path importance 的一個 strong/medium/weak signal。它會幫助我們在沒有 call graph depth 的情況下，先對 caller 的「位置」做一個初步的判斷。
    static std::string neutralInputOriginHint(const std::string &InputOrigin) {
        if (InputOrigin == "syntactic input-like argument" || InputOrigin == "syntactic user/file-like argument") {
            return "syntactic input-like argument detected";
        }
        if (InputOrigin == "parser path or derived parser state") {
            return "parser-derived argument pattern detected";
        }
        if (InputOrigin == "no call arguments") {
            return "no call arguments";
        }
        return "unclear from syntax";
    }

    /* 根據 caller 傳入的 arguments，產生一句人類可讀的 relevance 描述 */
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

    /* 根據 argument 的字面名稱，將其分類到不同的類別中
    例：foo(buf, len, ctx, path);被分成（buffer/pointer, length-like value, parser state, path/file resource)
    */
    static std::vector<std::string> classifyArgumentCategories(const std::vector<std::string> &ArgTexts) {
        std::string Combined = lowerCopy(joinStrings(ArgTexts, " "));
        std::vector<std::string> Categories;
        if (ArgTexts.empty()) Categories.push_back("no arguments");
        if (containsAny(Combined, {"dc", "ctx", "context", "state", "parser"})) Categories.push_back("parser state");
        if (containsAny(Combined, {"act", "action", "tag", "field", "opcode", "bytecode", "data", "chunk"})) Categories.push_back("action data");
        if (containsAny(Combined, {"len", "length", "size", "count", "max", "remain", "remaining"})) Categories.push_back("length-like value");
        if (containsAny(Combined, {"off", "offset", "pos", "position", "cursor", "idx", "index"})) Categories.push_back("offset/progress value");
        if (containsAny(Combined, {"buf", "buffer", "ptr", "pointer", "dst", "dest", "src"})) Categories.push_back("buffer/pointer");
        if (Categories.empty()) Categories.push_back("unclear from syntax");
        
        // New taxonomy-guided categories
        if (containsAny(Combined, {"path", "file", "dir", "fd", "root", "cwd"}))
            Categories.push_back("path/file resource");

        if (containsAny(Combined, {"cmd", "cmnd", "command", "argv", "exec"}))
            Categories.push_back("command/execution data");

        if (containsAny(Combined, {"uid", "gid", "user", "group", "runas", "cred", "role"}))
            Categories.push_back("identity/principal");

        if (containsAny(Combined, {"chroot", "root", "runchroot", "pivot", "namespace", "mount", "cwd"}))
            Categories.push_back("filesystem namespace state");

        if (containsAny(Combined, {"nss", "pam", "passwd", "shadow", "config", "policy", "lookup"}))
            Categories.push_back("trust/config lookup");

        if (containsAny(Combined, {"auth", "permission", "policy", "rule", "allow", "deny", "check"}))
            Categories.push_back("auth/policy decision");

        if (containsAny(Combined, {"env", "environ", "locale", "loader", "ld_preload"}))
            Categories.push_back("environment/runtime context");

        if (containsAny(Combined, {"cert", "x509", "ssl", "tls", "asn1", "crypto"}))
            Categories.push_back("crypto/certificate state");

        if (Categories.empty()) Categories.push_back("unclear from syntax");

        return uniqueStrings(Categories);
    }

    /* 看 caller 的 function name 是否像「處理流程上的重要 function」 */
    static bool callerNameLooksRelevant(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {"parser", "parse", "read", "decode", "load", "handle", "process", "scan", "check", "validate", "dispatch", "main"});
    }

    /* 看 caller 名稱是否像入口點或外部輸入接收點。 */
    static bool callerNameLooksLikeEntry(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {"main", "read", "recv", "request", "handle_request", "entry"});
    }

    /* 看 caller 名稱是否像 parser / decoder / validation path */
    static bool callerNameLooksParserLike(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {"parser", "parse", "decompile", "decode", "load", "scan", "check", "validate", "dispatch"});
    }

    /* 判斷 function 是否像 logging/debug/error helper */
    static bool isLoggingOrDebugHelper(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {
            "log", "debug", "trace", "warn", "warning", "error", "fatal",
            "print", "printf", "fprintf", "snprintf", "syslog", "audit"
        });
    }

    /* 看 arguments 字串是否像外部輸入資料 */
    static bool argsLookInputLike(const std::string &Args) {
        return containsAny(Args, {"buf", "buffer", "data", "input", "chunk", "packet", "file", "argv", "env", "user", "request", "stdin"});
    }

    /* 看 arguments 是否像 parser 結構化狀態 */
    static bool argsLookStructuredParserLike(const std::string &Args) {
        return containsAny(Args, {"state", "ctx", "context", "parser", "action", "tag", "field", "opcode", "len", "length", "size", "offset", "cursor"});
    }
    
    /* 幫 caller edge 打分數，根據 caller 傳入的 arguments 和 caller name，估計這條 caller relation 有多值得關注 */
    // 決定 callers[] 裡 top callers 的排序
    // 把比較可能承載外部輸入、parser 狀態、buffer/length/index 的 caller 排前面。
    // scoreCallerRelevance() 的分數是為了排序 caller，不是證明漏洞；
    // +3 給直接且高價值的 argument signal，+2 給較弱但有用的 caller/input context，+1 給 parser-derived hint，
    // 讓 caller_summary 優先顯示最可能承載外部輸入或 parser/control-path 資料的 caller。
    // 優先保留最能提供攻擊面、資料流、邊界條件、parser/control-path 線索的 caller，讓後續漏洞分析更快聚焦。
    static int scoreCallerRelevance(const FunctionInfo &Caller, const CallInfo &Call, const std::string &InputOrigin) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        int Score = 0;
        if (containsAny(Args, {"buf", "buffer", "data", "ptr", "pointer"})) Score += 3;
        if (containsAny(Args, {"len", "length", "size", "count", "max", "remain", "remaining"})) Score += 3;
        if (containsAny(Args, {"off", "offset", "pos", "position", "cursor", "idx", "index"})) Score += 3;
        if (containsAny(Args, {"state", "ctx", "context", "parser"})) Score += 3;
        if (callerNameLooksRelevant(Caller.funcName)) Score += 2;
        if (callerNameLooksLikeEntry(Caller.funcName) && argsLookInputLike(Args)) Score += 2;
        if (InputOrigin == "syntactic input-like argument" || InputOrigin == "syntactic user/file-like argument") Score += 2;
        if (InputOrigin == "parser path or derived parser state") Score += 1;
        return Score;
    }

    /* 判斷 caller 這條呼叫關係，是否看起來位在外部輸入或 parser/control path 上。 */
    //從 caller context 看，這個 function 是否可能位在外部輸入或 parser path 上，這是對 control path importance 的一個 strong/medium/weak signal。它會幫助我們在沒有 call graph depth 的情況下，先對 caller 的「位置」做一個初步的判斷。
    static std::string classifyInputPathHint(const FunctionInfo &Caller, const CallInfo &Call, const std::string &InputOrigin) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        bool HasInputArgs = argsLookInputLike(Args);
        bool HasParserArgs = argsLookStructuredParserLike(Args);
        bool EntryName = callerNameLooksLikeEntry(Caller.funcName);
        bool ParserName = callerNameLooksParserLike(Caller.funcName);

        if (EntryName && HasInputArgs) return "strong";
        if (ParserName && (HasInputArgs || HasParserArgs)) return "medium";
        return "weak";
    }

    /* 用一句話描述 caller 在 control path 裡的角色。 */
    //role_hint 是根據 caller 名稱、argument pattern、relevance score 產生的描述文字。
    static std::string summarizeControlPathRole(const FunctionInfo &Caller, const CallInfo &Call, int RelevanceScore) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        if (callerNameLooksLikeEntry(Caller.funcName) && argsLookInputLike(Args)) {
            return "entry-like caller with input-like arguments";
        }
        if (callerNameLooksRelevant(Caller.funcName) || containsAny(Args, {"state", "ctx", "parser", "offset", "cursor", "len", "length"})) {
            return "on the upstream parser/control path";
        }
        if (RelevanceScore >= 4) {
            return "receiving security-relevant data from its caller";
        }
        return "connected by a direct call, but control-path importance is unclear";
    }

    /* 判斷某個 function 名稱是否像 cleanup/free/lifetime helper。 */
    //cleanup helper 判斷
    static bool isCleanupOrFreeHelper(const std::string &Name) {
        std::string N = lowerCopy(Name);
        return containsAny(N, {
            "free",
            "delref",
            "close",
            "cleanup",
            "destroy",
            "release"
        });
    }

    /* 判斷某個 function 是否有高價值的安全操作 */
    //高價值 security operation 判斷，這些 operation 的出現通常是安全檢查、權限變更、重要資源存取等關鍵安全行為的 strong signal
    static bool hasHighValueSecurityOperation(const std::vector<std::string> &OperationClasses) {
        std::string Ops = lowerCopy(joinStrings(OperationClasses, " "));
        return containsAny(Ops, {
            "filesystem_namespace_transition",
            "privilege_identity_transition",
            "trust_config_lookup",
            "dynamic_code_loading",
            "auth_policy_gate",
            "command_execution",
            "crypto_certificate_validation"
        });
    }

    static CallerEdge buildCallerEdge(const FunctionInfo &Caller, const CallInfo &Call) {
        CallerEdge Edge;
        Edge.funcName = Caller.funcName;
        Edge.inputOrigin = classifyInputOrigin(Call.argTexts);
        Edge.inputPathHint = classifyInputPathHint(Caller, Call, Edge.inputOrigin);
        Edge.argTexts = Call.argTexts;
        Edge.argumentCategories = classifyArgumentCategories(Call.argTexts);
        Edge.relevance = summarizeCallerRelevance(Call.argTexts, Edge.inputOrigin);
        Edge.relevanceScore = scoreCallerRelevance(Caller, Call, Edge.inputOrigin);
        Edge.controlPathRole = summarizeControlPathRole(Caller, Call, Edge.relevanceScore);
        return Edge;
    }

    //避免同一個 function 因為同時出現 chroot 和 pivot_root，重複加入多個一樣的 filesystem_namespace_transition，造成分數膨脹。
    static void addOperationSignal(
        std::vector<OperationSignal> &Signals,
        const std::string &OperationClass,
        const std::string &CweFamily,
        const std::string &Evidence
    ){
        for(const auto &S : Signals){
            if(S.operationClass == OperationClass && S.cweFamily == CweFamily) return;
        }

        OperationSignal Signal;
        Signal.operationClass = OperationClass;
        Signal.cweFamily = CweFamily;
        Signal.evidence = Evidence;
        Signals.push_back(Signal);
    }

    // 根據 function name + source code 的關鍵字，偵測 callee 可能涉及哪些安全相關 operation。
    static std::vector<std::string> detectDangerSignals(const std::string &FuncName, const std::string &Code) {
        std::string Text = lowerCopy(FuncName + " " + Code); // 將callee 名稱和 callee 原始碼合併，轉小寫後搜尋關鍵字。
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

    /* 負責從 callee 名稱與原始碼抓安全語意：
    這個 callee 看起來在做什麼安全相關操作？
    它可能屬於哪類 weakness family？
    它在 caller/callee 關係中扮演什麼角色？ 
    */
    // 針對被呼叫者（Callee）的分析。根據 function name + source code 的關鍵字，偵測 callee 可能涉及哪些安全相關 operation。
    // Taxonomy-guided operation signals are kept separate from legacy string danger signals.
    static std::vector<OperationSignal> detectOperationSignals(const std::string &FuncName, const std::string &Code) {
        std::string Text = lowerCopy(FuncName + " " + Code);
        std::vector<OperationSignal> Signals;

        // 1. Memory write / buffer operation
        if(containsAny(Text,{  "memcpy", "memmove", "bcopy", "strcpy", "strncpy","strcat", "strncat", "sprintf", "snprintf","write", "append", "dst", "dest", "src"})){
            addOperationSignal(
                Signals, 
                "memory_write",
                "memory_safety",
                "Function appears to perform memory, string, or buffer write operations.");
        }
            // 2. Size / index / length computation
        if (containsAny(Text, {
            "len", "length", "size", "count", "nbytes","idx", "index", "offset", "remain", "remaining", "malloc", "calloc", "realloc"})) {
            addOperationSignal(
                Signals,
                "size_index_arithmetic",
                "integer_size",
                "Function uses size, length, index, offset, or allocation-related values.");
        }

        // 3. Allocation / lifetime
        if (containsAny(Text, {"malloc", "calloc", "realloc", "free", "new ", "delete "})) {
            addOperationSignal(
                Signals,
                "allocation_lifetime",
                "resource_lifecycle",
                "Function manages allocation, deallocation, or object lifetime.");
        }

        // 4. Parser / decoder
        if (containsAny(Text, {"parse", "parser", "decode", "decompile", "read","next", "advance", "consume", "token", "tag", "field", "opcode", "chunk", "state"})) {
            addOperationSignal(
                Signals,
                 "parser_decoder",
                "input_validation_parser",
                "Function appears to parse, decode, or advance structured input state.");
        }

        // 5. Path / file / resource resolution
        if (containsAny(Text, {"path", "file", "dir", "fd", "open", "fopen", "stat", "lstat", "realpath", "canonical", "resolve", "symlink", "readlink"})) {
            addOperationSignal(
                Signals,
                "path_file_resolution",
                "path_file_resource",
                "Function appears to resolve paths, files, directories, or filesystem resources.");
        }

        // 6. Command execution / command resolution
        if (containsAny(Text, {"system", "exec", "execve", "execl", "execv", "popen", "command", "cmd", "cmnd", "argv"})) {
            addOperationSignal(
                Signals,
                "command_execution",
                "injection_command_execution",
                "Function appears to execute, construct, or resolve commands.");
        }

        // 7. Privilege / identity transition
        if (containsAny(Text, {"setuid", "seteuid", "setreuid", "setresuid", "setgid", "setegid", "setregid", "setresgid", "setgroups", "initgroups", "uid", "gid", "user", "group", "runas", "cred", "capset", "cap_"})) {
            addOperationSignal(
                Signals,
                "privilege_identity_transition",
                "privilege_access_control",
                "Function appears to manipulate user/group identity, credentials, or privilege state.");
        }

        // 8. Filesystem namespace / root transition
        if (containsAny(Text, {"chroot", "pivot_root", "unpivot", "rootdir", "runchroot", "chdir", "fchdir", "setns", "mount", "namespace", "cwd"})) {
            addOperationSignal(
                Signals,
                "filesystem_namespace_transition",
                "privilege_access_control",
                "Function appears to change filesystem root, working directory, or namespace context.");
        }

        // 9. Trust/config lookup: NSS/PAM/passwd/group/config/policy
        if (containsAny(Text, { "nss", "pam", "passwd", "shadow", "group", "getpwnam", "getpwuid", "getgrnam", "getgrgid", "lookup", "nsswitch", "config", "policy"})) {
            addOperationSignal(
                Signals,
                "trust_config_lookup",
                "trust_boundary_security_decision",
                "Function appears to read identity, policy, configuration, or trusted lookup data.");
        }

        // 10. Dynamic code loading
        if (containsAny(Text, { "dlopen", "dlsym", "loadlibrary", "module", "plugin", ".so", "shared object", "library"})) {
            addOperationSignal(
                Signals,
                "dynamic_code_loading",
                "trust_boundary_security_decision",
                "Function appears to load external code, modules, plugins, or dynamic libraries.");
        }

        // 11.  Authorization / policy gate
        if (containsAny(Text, { "check", "validate", "verify", "match", "allow", "deny", "policy", "permission", "authorize", "auth", "sudoers", "rule"})) {
            addOperationSignal(
                Signals,
                "auth_policy_gate",
                "privilege_access_control",
                "Function appears to participate in authorization, policy, validation, or permission checks.");
        }
        
        // 12. Crypto / certificate validation
        if (containsAny(Text, { "x509", "cert", "certificate", "ssl", "tls", "verify", "signature", "crypto", "asn1", "punycode", "name constraint"})) {
            addOperationSignal(
                Signals,
                "crypto_certificate_validation",
                "crypto_auth_certificate",
                "Function appears related to cryptographic, certificate, or security validation logic.");
        }

        // 13. Race / ordering / locking
        if (containsAny(Text, { "lock", "unlock", "mutex", "race", "atomic", "before", "after", "toctou"})) {
            addOperationSignal(
                Signals,
                "race_ordering",
                "race_ordering_toctou",
                "Function appears to involve synchronization, ordering, or check-use timing.");
        }

        // 14. Environment / runtime context
        if (containsAny(Text, { "env", "environ", "getenv", "setenv", "putenv", "locale", "loader", "ld_preload", "home", "shell" })) {
            addOperationSignal(
                Signals,
                "environment_runtime_context",
                "trust_boundary_security_decision",
                "Function appears to depend on environment or runtime context.");
        }

        return Signals;
    }

    /* 把 signal 拆成可統計欄位，從 vector<OperationSignal> 裡抽出 operation class 清單，輸出JSON 裡的：
    "operation_classes": [...]
    "operation_signals": [...] */
    //輸出可統計欄位
    static std::vector<std::string> extractOperationClasses(const std::vector<OperationSignal> &Signals){
        std::vector<std::string> Result;
        for(const auto &S : Signals){
            Result.push_back(S.operationClass);
        }
        return uniqueStrings(Result);
    }

    /* 把 signal 拆成可統計欄位，從 vector<OperationSignal> 裡抽出 CWE family 清單，輸出JSON 裡的：
    "cwe_families": [...] */
    static std::vector<std::string> extractCweFamilies(const std::vector<OperationSignal> &Signals){
        std::vector<std::string> Result;
        for (const auto &S : Signals) {
            Result.push_back(S.cweFamily);
        }
        return uniqueStrings(Result);
    }

    /* 把 operation signal 變成人類可讀的短摘要 */
    static std::vector<std::string> summarizeOperationSignals(const std::vector<OperationSignal> &Signals){
        std::vector<std::string> Result;
        for (const auto &S : Signals) {
            Result.push_back(S.operationClass + " -> " + S.cweFamily);
        }
        return uniqueStrings(Result);
    }

    
    /* 根據 callee 的 operation signals，產生一句人類可讀的 relevance 描述 */
    static std::string summarizeCalleeRelevance(const std::vector<std::string> &Signals, const std::vector<std::string> &OperationClasses) {
        std::vector<std::string> Parts;
        if (!Signals.empty()) {
            Parts.push_back("local signals: " + joinStrings(Signals, ", "));
        }
        if (!OperationClasses.empty()) {
            Parts.push_back("operation signals: " + joinStrings(OperationClasses, ", "));
        }
        if (Parts.empty()) return "has no obvious local signals";
        return joinStrings(Parts, " "); 
    }

    /* 根據 callee 的 signals / operation classes，給它一個角色描述。
       則把這些 signal 轉成 JSON 中可讀、可排序、可供後續分析使用的摘要。 */
    // summarizeCalleeRoleHint() 是為了把 callee 的底層安全 signals 轉成高階角色描述，讓 callee_summary 更容易讀、能區分 downstream evidence 類型，也幫後續人工或 LLM 分析快速聚焦。
    static std::string summarizeCalleeRoleHint(const std::vector<std::string> &Signals, const std::vector<std::string> &OperationClasses) {
        std::string SignalText = lowerCopy(joinStrings(Signals, " "));
        std::string OperationText = lowerCopy(joinStrings(OperationClasses, " "));
        if (containsAny(OperationText, {"filesystem_namespace_transition", "privilege_identity_transition"})) {
            return "downstream privilege or namespace state-transition helper";
        }

        if (containsAny(OperationText, {"trust_config_lookup", "dynamic_code_loading"})) {
            return "downstream trust/config lookup or dynamic loading helper";
        }

        if (containsAny(OperationText, {"auth_policy_gate"})) {
            return "downstream authorization or policy gate helper";
        }

        if (containsAny(OperationText, {"path_file_resolution", "command_execution"})) {
            return "downstream path or command resolution helper";
        }

        if (containsAny(OperationText, {"crypto_certificate_validation"})) {
            return "downstream crypto/certificate validation helper";
        }       

        if (containsAny(OperationText, {"memory_write", "allocation_lifetime"})) {
            return "downstream memory/data operation helper";
        }

        if (containsAny(SignalText, {"validation logic", "parser state update", "type conversion/cast"})) {
            return "downstream validation/state helper";
        }

        if (containsAny(SignalText, {"memory copy", "allocation", "buffer write", "string handling", "stack manipulation"})) {
            return "downstream dangerous primitive helper";
        }
        return "direct helper";
    }

    /* 幫 callee_summary 判斷哪些 callee 比較值得被選進 top callees */
    static int scoreCalleeDangerSignals(const std::vector<std::string> &Signals) {
        int Score = 0;
        for (const auto &Signal : Signals) {
            if (Signal == "memory copy" || Signal == "buffer write") Score += 2;
            else if (Signal == "allocation" || Signal == "string handling" || Signal == "stack manipulation") Score += 1;
            else if (Signal == "parser state update" || Signal == "length/remaining/consumed update" || Signal == "parser progress update") Score += 1;
            else if (Signal == "type conversion/cast" || Signal == "validation logic" || Signal == "length-dependent operation") Score += 1;
        }
        return std::min(Score, 2);
    }

    /* detectOperationSignals() 偵測出來的高階操作類型， 判斷這個 callee 本身涉及的操作有多安全敏感，供 callee 排序與 tie-breaker 使用 */
    static int scoreCalleeOperationSignals(const std::vector<OperationSignal> &Signals) {
        int Score = 0;

        for (const auto &Signal : Signals) {
            const std::string &Cls = Signal.operationClass;

            if (
                Cls == "memory_write" ||
                Cls == "command_execution" ||
                Cls == "privilege_identity_transition" ||
                Cls == "filesystem_namespace_transition" ||
                Cls == "dynamic_code_loading"
            ) {
                Score += 2;
            } else if (
                Cls == "trust_config_lookup" ||
                Cls == "auth_policy_gate" ||
                Cls == "path_file_resolution" ||
                Cls == "crypto_certificate_validation"
            ) {
                Score += 2;
            } else if (
                Cls == "size_index_arithmetic" ||
                Cls == "allocation_lifetime" ||
                Cls == "parser_decoder" ||
                Cls == "race_ordering" ||
                Cls == "environment_runtime_context"
            ) {
                Score += 1;
            }     
        }
        return std::min(Score, 6);
    }

    
    /* （也就是 classifyArgumentCategories() 的結果）看 caller 傳給 callee 的 arguments 像不像安全重要資料  */
    static int scoreCalleeArgumentFlow(const std::vector<std::string> &Categories) {
        int Score = 0;
        for (const auto &Category : Categories) {
            if (Category == "buffer/pointer") Score += 4;
            else if (Category == "length-like value") Score += 4;
            else if (Category == "parser state") Score += 3;
            else if (Category == "action data") Score += 3;
            else if (Category == "offset/progress value") Score += 3;

            // New taxonomy-guided categories
            else if (Category == "path/file resource") Score += 4;
            else if (Category == "command/execution data") Score += 4;
            else if (Category == "identity/principal") Score += 4;
            else if (Category == "filesystem namespace state") Score += 5;
            else if (Category == "trust/config lookup") Score += 5;
            else if (Category == "auth/policy decision") Score += 4;
            else if (Category == "environment/runtime context") Score += 4;
            else if (Category == "crypto/certificate state") Score += 4;
        }
        return std::min(Score, 8);
    }

    /* 為了keyword 訊號較弱，容易誤判，所以設計看 callee 自己的 name/code 是否像安全相關邏輯 */
    //有些 function 沒有明顯 memory operation，但位於 security-critical path 上，仍然值得關注。
    // 例如一個叫 check_policy 的 function，裡面沒有明顯的 memory operation，但它的名字和內容都強烈暗示它在做安全檢查。
    // 這種情況下，我們可以給它一個額外的分數加成，以反映它在安全上下文中的重要性。
    // 為什麼只最多 2？ 因為它是根據 function name/code 字串做 keyword search，容易有雜訊。
    static int scoreSecurityContext(const std::string &FuncName, const std::string &Code) {
        
        if (isLoggingOrDebugHelper(FuncName)) {
            return 0;
        }

        std::string Text = lowerCopy(FuncName + " " + Code);
        int Score = 0;


        if (containsAny(Text, {
            "sudo", "sudoers", "policy", "auth", "permission",
            "check", "validate", "verify", "match", "allow", "deny"
        })) {
            Score += 1;
        }

        if (containsAny(Text, {
            "root", "uid", "gid", "runas", "priv", "credential",
            "chroot", "nss", "pam"
        })) {
            Score += 1;
        }

        if (containsAny(Text, {
            "x509", "cert", "ssl", "tls", "crypto", "signature"
        })) {
            Score += 1;
        }

        return std::min(Score, 2);
    }


    /* 如果只輸出 direct call graph，資訊會太粗："callees": ["copy_data", "log_debug", "cleanup", "check_policy"]
         這裡要幫 callee_summary 補充更多訊息，讓它更容易被人工或 LLM 分析聚焦。    
         scoreCalleeRoleMatch（）不是 callee 有 signal 就重要，而是「傳進去的資料」和「callee 的功能」有沒有形成安全相關關係。
    */
    /*判斷「傳給 callee 的參數類型」和「callee 本身看起來在做的事」是否匹配。問：目前 function 傳進去的資料，是否剛好符合 callee 的敏感操作？*/
    static int scoreCalleeRoleMatch(
        const std::string &FuncName,
        const std::vector<std::string> &Categories,
        const std::vector<std::string> &Signals,
        const std::vector<OperationSignal> &OperationSignals
    ) {
        std::string Name = lowerCopy(FuncName);
        std::string CategoryText = lowerCopy(joinStrings(Categories, " "));
        std::string SignalText = lowerCopy(joinStrings(Signals, " "));
        std::string OperationText = lowerCopy(joinStrings(extractOperationClasses(OperationSignals), " "));
        int Score = 0;

        // Existing memory/parser-oriented role matching 
        if (
            containsAny(CategoryText, {"buffer", "pointer"})
            && (containsAny(SignalText, {"memory copy", "buffer write", "string handling"}) || containsAny(Name, {"copy", "str", "mem", "put", "write"}))
        ) {
            Score += 3;
        }
        if (
            containsAny(CategoryText, {"length-like"})
            && (containsAny(SignalText, {"length", "remaining", "consumed"}) || containsAny(Name, {"len", "length", "size", "count", "strlen"}))
        ) {
            Score += 3;
        }
        if (
            containsAny(CategoryText, {"parser state", "offset", "progress"})
            && (containsAny(SignalText, {"parser state", "parser progress", "validation", "type conversion"}) || containsAny(Name, {"parse", "decompile", "read", "next", "advance", "state"}))
        ) {
            Score += 3;
        }
        if (
            containsAny(CategoryText, {"action data"})
            && (containsAny(SignalText, {"parser state", "validation", "type conversion", "string handling"}) || containsAny(Name, {"action", "tag", "field", "opcode", "get"}))
        ) {
            Score += 3;
        }

        // New taxonomy-guided role matching
        if (
            containsAny(CategoryText, {"path/file resource"})
            && containsAny(OperationText, {"path_file_resolution", "filesystem_namespace_transition"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"command/execution data"})
            && containsAny(OperationText, {"command_execution", "path_file_resolution"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"identity/principal"})
            && containsAny(OperationText, {"privilege_identity_transition", "trust_config_lookup", "auth_policy_gate"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"filesystem namespace state"})
            && containsAny(OperationText, {"filesystem_namespace_transition", "path_file_resolution", "trust_config_lookup"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"trust/config lookup"})
            && containsAny(OperationText, {"trust_config_lookup", "dynamic_code_loading", "auth_policy_gate"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"auth/policy decision"})
            && containsAny(OperationText, {"auth_policy_gate", "privilege_identity_transition", "trust_config_lookup"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"environment/runtime context"})
            && containsAny(OperationText, {"environment_runtime_context", "dynamic_code_loading", "trust_config_lookup"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"crypto/certificate state"})
            && containsAny(OperationText, {"crypto_certificate_validation", "parser_decoder"})
        ) {
            Score += 3;
        }

        return std::min(Score, 8); // 封頂的原因是避免一個 callee 因為同時命中很多 keyword 而分數爆炸。它是排序 heuristic，不是漏洞評分。
    }

    /* keyword signal 要怎麼保守輸出？
    detectDangerSignals() 會產生比較直接、甚至有點強烈的詞：memory copy, buffer write, string handling, parser state update，但這些是 keyword heuristic。
    看到 memcpy 不代表一定有 overflow；看到 check 不代表一定是安全驗證。
    所以 neutralizeCalleeSignals() 的目的就是：把「可能危險」的 keyword signal 轉成比較保守、中性的描述，避免輸出把線索講成結論。
     */
    static std::vector<std::string> neutralizeCalleeSignals(const std::vector<std::string> &Signals) {
        std::vector<std::string> Neutral;
        for (const auto &Signal : Signals) {
            if (Signal == "memory copy" || Signal == "buffer write") Neutral.push_back("memory/buffer operation");
            else if (Signal == "length-dependent operation" || Signal == "length/remaining/consumed update") Neutral.push_back("length-related logic");
            else if (Signal == "parser state update") Neutral.push_back("parser state logic");
            else if (Signal == "parser progress update") Neutral.push_back("parser progress logic");
            else if (Signal == "stack manipulation") Neutral.push_back("stack operation");
            else Neutral.push_back(Signal);
        }

        return uniqueStrings(Neutral);
    }


    static CalleeEdge buildCalleeEdge(const CallInfo &Call, const std::map<std::string, FunctionInfo *> &ByName) {
        auto It = ByName.find(Call.calleeName);
        std::string CalleeCode = (It != ByName.end()) ? It->second->code : "";
        std::vector<std::string> Signals = detectDangerSignals(Call.calleeName, CalleeCode);
        std::vector<OperationSignal> OperationSignals = detectOperationSignals(Call.calleeName, CalleeCode);

        CalleeEdge Edge;
        Edge.funcName = Call.calleeName;
        Edge.argTexts = Call.argTexts;
        Edge.argumentCategories = classifyArgumentCategories(Call.argTexts);
        Edge.dangerSignals = Signals;
        Edge.localSignals = neutralizeCalleeSignals(Signals);
        // New taxonomy-guided fields
        Edge.operationSignals = OperationSignals;
        Edge.operationClasses = extractOperationClasses(OperationSignals);
        Edge.cweFamilies = extractCweFamilies(OperationSignals);
        Edge.relevance = summarizeCalleeRelevance(Signals, Edge.operationClasses);
        Edge.roleHint = summarizeCalleeRoleHint(Signals, Edge.operationClasses);

        Edge.argumentFlowScore = scoreCalleeArgumentFlow(Edge.argumentCategories);
        Edge.roleMatchScore = scoreCalleeRoleMatch(Edge.funcName, Edge.argumentCategories, Signals, OperationSignals);
        Edge.dangerSignalScore = scoreCalleeDangerSignals(Signals);
        Edge.operationSignalScore = scoreCalleeOperationSignals(OperationSignals);
        Edge.securityContextScore = scoreSecurityContext(Edge.funcName, CalleeCode);

        // New relevance formula:
        Edge.relevanceScore = Edge.argumentFlowScore + Edge.roleMatchScore + Edge.dangerSignalScore + Edge.securityContextScore;

        // Cleanup/free helpers are useful supporting context,
        // but should not dominate top-k unless they contain high-value security operations.
        /* cleanup/free helper 可以是重要上下文，但如果它沒有高價值安全操作，就不要讓它分數太高、擠掉更重要的 callee。 */
        if (isCleanupOrFreeHelper(Edge.funcName) &&
            !hasHighValueSecurityOperation(Edge.operationClasses)) {
            Edge.relevanceScore = std::min(Edge.relevanceScore, 10);
        }     
        
        return Edge;
    }

    static constexpr size_t kMaxCallContextEdges = 5;

    /* 控制 callee_summary 只留下最值得看的下游關係:
        1. 過濾掉 relevanceScore == 0 的 callee
        2. 依安全分析價值排序
        3. 最多保留 kMaxCallContextEdges，也就是 5 個
    */
    static std::vector<CalleeEdge> selectTopCallees(const std::vector<CalleeEdge> &Edges) {
        std::vector<CalleeEdge> Ranked;
        for (const auto &Edge : Edges) {
            if (Edge.relevanceScore > 0) Ranked.push_back(Edge);
        }
        std::stable_sort(Ranked.begin(), Ranked.end(), [](const CalleeEdge &A, const CalleeEdge &B) {
            if (A.relevanceScore != B.relevanceScore) return A.relevanceScore > B.relevanceScore;
            if (A.argumentFlowScore != B.argumentFlowScore) return A.argumentFlowScore > B.argumentFlowScore;
            if (A.roleMatchScore != B.roleMatchScore) return A.roleMatchScore > B.roleMatchScore;
            if (A.operationSignalScore != B.operationSignalScore) return A.operationSignalScore > B.operationSignalScore;
            if (A.securityContextScore != B.securityContextScore) return A.securityContextScore > B.securityContextScore;
            return A.funcName < B.funcName; // Tie-breaker for consistent ordering
        });

        if (Ranked.size() > kMaxCallContextEdges) Ranked.resize(kMaxCallContextEdges);
        return Ranked;
    }

    /* 把 top callees 轉成人類/LLM 好讀的摘要文字 */
    static std::vector<std::string> buildCalleeSummaryLines(const std::vector<CalleeEdge> &TopEdges) {
        std::vector<std::string> Lines;
        if (TopEdges.empty()) {
            Lines.push_back("No direct callee with local signals was selected for this function.");
            Lines.push_back("Note: callee signals are downstream evidence only unless the callee return value controls current-function progress.");
            return Lines;
        }

        for (const auto &Edge : TopEdges) {
            std::string Args = Edge.argTexts.empty() ? "none" : joinStrings(Edge.argTexts, ", ");
            std::string Categories = Edge.argumentCategories.empty() ? "unclear from syntax" : joinStrings(Edge.argumentCategories, ", ");
            std::string Signals = Edge.localSignals.empty() ? "none observed" : joinStrings(Edge.localSignals, ", ");
            std::string Ops = Edge.operationClasses.empty() ? "none observed" : joinStrings(Edge.operationClasses, ", ");
            std::string Families = Edge.cweFamilies.empty() ? "none observed" : joinStrings(Edge.cweFamilies, ", ");

            Lines.push_back("Calls " + Edge.funcName + " with arguments: " + Args + ".");
            Lines.push_back("Passed argument categories: " + Categories + ".");
            Lines.push_back("Callee has local signals: " + Signals + ".");
            Lines.push_back("Callee has operation signals: " + Ops + ".");
            Lines.push_back("Callee has CWE families: " + Families + ".");
        }
        Lines.push_back("Note: callee signals are downstream evidence only unless the callee return value controls current-function progress.");
        return Lines;
    }

    /*安全地把 vector<string> 輸出成 JSON array*/
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

    /**
     * Builds a JSON string representing cross-function direct evidence.
     * @param EvidenceList The list of direct evidence to include.
     * @return A JSON string containing the evidence.
     */
    /*把「跨函式但可歸因目前 function」的直接證據輸出成 JSON*/
    static std::string buildCrossFunctionDirectEvidenceJson(const std::vector<DirectEvidence> &EvidenceList) {
        std::vector<std::string> Lines;

        if (EvidenceList.empty()) {
            Lines.push_back("No cross-function direct evidence was detected in the current function body.");
        } else {
            for (const auto &Evidence : EvidenceList) {
                if (Evidence.kind == "security_boundary_transition_around_resolution") {
                    Lines.push_back(
                        "Current function performs " + Evidence.expression +
                        "; treat this security ordering as direct current-function evidence, not merely callee supporting evidence."
                    );
                    Lines.push_back(
                        "Pattern: boundary transition -> name/path/command/authority-dependent resolution."
                    );
                } else {
                    Lines.push_back(
                        "Current function updates " + Evidence.lhs +
                        " using return value from " + Evidence.calleeName +
                        "; treat this as direct current-function evidence, not merely callee supporting evidence."
                    );
                    Lines.push_back(
                        "Pattern: callee return value -> current loop/index/progress variable -> next traversal step."
                    );
                }
            }
        }

        std::ostringstream OS;
        OS << "{\"summary_lines\": " << buildJsonStringArray(Lines)
           << ", \"patterns\": [";

        for (size_t I = 0; I < EvidenceList.size(); ++I) {
            if (I) OS << ", ";
            const auto &Evidence = EvidenceList[I];
            OS << "{"
               << "\"kind\": \"" << escapeJson(Evidence.kind) << "\", "
               << "\"lhs\": \"" << escapeJson(Evidence.lhs) << "\", "
               << "\"callee\": \"" << escapeJson(Evidence.calleeName) << "\", "
               << "\"expression\": \"" << escapeJson(Evidence.expression) << "\", "
               << "\"bound_check_observed\": " << (Evidence.boundCheckObserved ? "true" : "false") << ", "
               << "\"evidence_strength\": \"" << escapeJson(Evidence.evidenceStrength) << "\", "
               << "\"explanation\": \"" << escapeJson(Evidence.explanation) << "\", "
               << "\"ranking_effect\": \"may increase root_cause_likelihood, decision_or_validation_risk, state_ordering_consistency_risk, and failure_trigger_plausibility when current-function ordering controls traversal, authority, or resolution semantics\""
               << "}";
        }

        OS << "]}";
        return OS.str();
    }

    /* 一個 function 可能被很多 caller 呼叫，不可能每個都詳細輸出，所以要選出最重要的 caller。 */
    static std::vector<CallerEdge> selectTopCallers(const std::vector<CallerEdge> &Edges) {
        std::vector<CallerEdge> Ranked = Edges;
        std::stable_sort(Ranked.begin(), Ranked.end(), [](const CallerEdge &A, const CallerEdge &B) {
            return A.relevanceScore > B.relevanceScore; //relevanceScore 來自scoreCallerRelevance()
        });
        if (Ranked.size() > kMaxCallContextEdges) Ranked.resize(kMaxCallContextEdges);
        return Ranked;
    }

    /*產生 caller_summary.summary_lines 的第一句主摘要。*/
    static std::string buildCallerSummaryLine(const std::vector<CallerEdge> &TopEdges) {
        if (TopEdges.empty()) return "No direct caller was found for this function in the current translation unit.";

        const CallerEdge &Top = TopEdges.front();
        std::string Args = Top.argTexts.empty() ? "none" : joinStrings(Top.argTexts, ", ");
        std::string Categories = Top.argumentCategories.empty() ? "unclear from syntax" : joinStrings(Top.argumentCategories, ", ");
        std::string Line = "Caller relation: " + Top.funcName + " calls current function with arguments: " + Args + ".";
        Line += " Passed argument categories: " + Categories + ".";
        if (TopEdges.size() > 1) {
            std::vector<std::string> OtherNames;
            for (size_t I = 1; I < TopEdges.size(); ++I) OtherNames.push_back(TopEdges[I].funcName);
            Line += " Other selected caller: " + joinStrings(OtherNames, ", ") + ".";
        }
        return Line;
    }

    /* 產生完整的 caller summary lines。 */
    static std::vector<std::string> buildCallerSummaryLines(const std::vector<CallerEdge> &TopEdges) {
        std::vector<std::string> Lines;
        Lines.push_back(buildCallerSummaryLine(TopEdges));

        if (TopEdges.empty()) {
            Lines.push_back("Input origin is unclear from direct caller context.");
            Lines.push_back("Current function may be an entry point or may be called outside the current translation unit.");
            return Lines;
        }

        const CallerEdge &Top = TopEdges.front();
        Lines.push_back("Input path evidence level: " + Top.inputPathHint + ".");
        Lines.push_back("Note: caller context is upstream relation evidence only, not direct evidence for the current function body.");
        return Lines;
    }
    /*輸出完整的 JSON 欄位： "caller_summary": { ... } */
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
               << "\"relation_kind\": \"" << escapeJson(TopEdges[I].relationKind) << "\", "
               << "\"relevance\": \"" << escapeJson(TopEdges[I].relevance) << "\", "
               << "\"arg_texts\": " << buildJsonStringArray(TopEdges[I].argTexts) << ", "
               << "\"argument_categories\": " << buildJsonStringArray(TopEdges[I].argumentCategories) << ", "
               << "\"input_path_hint\": \"" << escapeJson(TopEdges[I].inputPathHint) << "\", "
               << "\"input_path_evidence\": \"" << escapeJson(TopEdges[I].inputPathHint) << "\", "
               << "\"input_origin_hint\": \"" << escapeJson(neutralInputOriginHint(TopEdges[I].inputOrigin)) << "\", "
               << "\"relevance_score\": " << TopEdges[I].relevanceScore
               << "}";
        }
        OS << "]}";
        return OS.str();
    }

    /*輸出完整的 JSON 欄位："callee_summary": { ... } */
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
                << "\"arg_texts\": " << buildJsonStringArray(TopEdges[I].argTexts) << ", "
                << "\"argument_categories\": " << buildJsonStringArray(TopEdges[I].argumentCategories) << ", "

                // Existing fields
                << "\"local_signals\": " << buildJsonStringArray(TopEdges[I].localSignals) << ", "

                // New taxonomy-guided fields
                << "\"operation_signals\": " << buildJsonStringArray(TopEdges[I].operationClasses) << ", "
                << "\"weakness_families\": " << buildJsonStringArray(TopEdges[I].cweFamilies) << ", "
                << "\"operation_classes\": " << buildJsonStringArray(TopEdges[I].operationClasses) << ", "
                << "\"cwe_families\": " << buildJsonStringArray(TopEdges[I].cweFamilies) << ", "

                << "\"evidence_scope\": \"" << escapeJson(TopEdges[I].evidenceScope) << "\", "
                << "\"is_current_function_evidence\": " << (TopEdges[I].isCurrentFunctionEvidence ? "true" : "false") << ", "
                << "\"is_downstream_evidence\": " << (TopEdges[I].isDownstreamEvidence ? "true" : "false") << ", "
                << "\"downstream_signal_hint\": " << buildJsonStringArray(TopEdges[I].dangerSignals) << ", "

                // Existing scores
                << "\"argument_flow_score\": " << TopEdges[I].argumentFlowScore << ", "
                << "\"role_match_score\": " << TopEdges[I].roleMatchScore << ", "
                << "\"local_signal_score\": " << TopEdges[I].dangerSignalScore << ", "

                // New taxonomy-guided scores
                << "\"operation_signal_score\": " << TopEdges[I].operationSignalScore << ", "
                << "\"security_context_score\": " << TopEdges[I].securityContextScore << ", "

                // Final callee relevance score
                << "\"relevance_score\": " << TopEdges[I].relevanceScore
                << "}";

            
        }
        OS << "]}";
        return OS.str();
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


// ========================================================
// 1. ASTFrontendAction: 負責建立 ASTConsumer
// ========================================================
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
