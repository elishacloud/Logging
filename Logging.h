#pragma once

#define WIN32_LEAN_AND_MEAN
#include <fstream>
#include <ostream>
#include <type_traits>

#define LOG_ONCE(msg) \
	static bool isAlreadyLogged##__LINE__ = false; \
	if (!isAlreadyLogged##__LINE__) \
	{ \
		Logging::Log() << msg; \
		isAlreadyLogged##__LINE__ = true; \
	}

#ifndef DINPUTTO8NOLOG
extern std::ofstream LOG;
#endif

std::ostream& operator<<(std::ostream& os, const char* str);
std::ostream& operator<<(std::ostream& os, const unsigned char* data);
std::ostream& operator<<(std::ostream& os, const WCHAR* wstr);
std::ostream& operator<<(std::ostream& os, const DEVMODEA& dm);
std::ostream& operator<<(std::ostream& os, const DEVMODEW& dm);
std::ostream& operator<<(std::ostream& os, const RECT& rect);
std::ostream& operator<<(std::ostream& os, HDC__& dc);
std::ostream& operator<<(std::ostream& os, HWND__& hwnd);
std::ostream& operator<<(std::ostream& os, const CWPSTRUCT& cwrp);
std::ostream& operator<<(std::ostream& os, const CWPRETSTRUCT& cwrp);

namespace Logging
{
	using ::operator<<;

	template <typename Num>
	struct Hex
	{
		explicit Hex(Num val) : val(val) {}
		Num val;
	};

	template <typename Num> Hex<Num> hex(Num val) { return Hex<Num>(val); }

	template <typename Elem>
	struct Array
	{
		Array(const Elem* elem, const unsigned long size) : elem(elem), size(size) {}
		const Elem* elem;
		const unsigned long size;
	};

	template <typename Elem>
	Array<Elem> array(const Elem* elem, const unsigned long size)
	{
		return Array<Elem>(elem, size);
	}

	template <typename T>
	struct Out
	{
		explicit Out(const T& val) : val(val) {}
		const T& val;
	};

	template <typename T> Out<T> out(const T& val) { return Out<T>(val); }

	class Log
	{
	public:
		Log();
		~Log();

		template <typename T>
		Log& operator<<(const T& t)
		{
			LOG << t;
			return *this;
		}

		static bool isPointerDereferencingAllowed() { return s_isLeaveLog || 0 == s_outParamDepth; }

	protected:
		template <typename... Params>
		Log(const char* prefix, const char* funcName, Params... params) : Log()
		{
			LOG << prefix << ' ' << funcName << '(';
			toList(params...);
			LOG << ')';
		}

	private:
		friend class LogLeaveGuard;
		template <typename T> friend std::ostream& operator<<(std::ostream& os, Out<T> out);

		void toList()
		{
		}

		template <typename Param>
		void toList(Param param)
		{
			LOG << param;
		}

		template <typename Param, typename... Params>
		void toList(Param firstParam, Params... remainingParams)
		{
			LOG << firstParam << ", ";
			toList(remainingParams...);
		}

		static DWORD s_outParamDepth;
		static bool s_isLeaveLog;
	};

	class LogParams;

	class LogFirstParam
	{
	public:
		LogFirstParam(std::ostream& os) : m_os(os) {}
		template <typename T> LogParams operator<<(const T& val) { m_os << val; return LogParams(m_os); }

	protected:
		std::ostream& m_os;
	};

	class LogParams
	{
	public:
		LogParams(std::ostream& os) : m_os(os) {}
		template <typename T> LogParams& operator<<(const T& val) { m_os << ',' << val; return *this; }

		operator std::ostream&() { return m_os; }

	private:
		std::ostream& m_os;
	};

	class LogStruct : public LogFirstParam
	{
	public:
		LogStruct(std::ostream& os) : LogFirstParam(os) { m_os << '{'; }
		~LogStruct() { m_os << '}'; }
	};

	// Added ***
	class LogStructNull
	{
	public:
		LogStructNull(std::ostream& os) : m_os(os) { m_os << '{'; }
		~LogStructNull() { m_os << '}'; }
		template <typename T> LogStructNull& operator<<(const T& val) { m_os << val; return *this; }

		operator std::ostream&() { return m_os; }

	private:
		std::ostream& m_os;
	};

	typedef Log LogDebug;

	class LogEnter : private Log
	{
	public:
		template <typename... Params>
		LogEnter(const char* funcName, Params... params) : Log("-->", funcName, params...)
		{
		}
	};

	class LogLeaveGuard
	{
	public:
		LogLeaveGuard() { Log::s_isLeaveLog = true; }
		~LogLeaveGuard() { Log::s_isLeaveLog = false; }
	};

	class LogLeave : private LogLeaveGuard, private Log
	{
	public:
		template <typename... Params>
		LogLeave(const char* funcName, Params... params) : Log("<--", funcName, params...)
		{
		}

		template <typename Result>
		void operator<<(const Result& result)
		{
			static_cast<Log&>(*this) << " = " << std::hex << result << std::dec;
		}
	};

	template <typename Num>
	std::ostream& operator<<(std::ostream& os, Hex<Num> hex)
	{
		os << "0x" << std::hex << hex.val << std::dec;
		return os;
	}

	template <typename Elem>
	std::ostream& operator<<(std::ostream& os, Array<Elem> array)
	{
		os << '[';
		if (Log::isPointerDereferencingAllowed())
		{
			if (0 != array.size)
			{
				os << array.elem[0];
			}
			for (unsigned long i = 1; i < array.size; ++i)
			{
				os << ',' << array.elem[i];
			}
		}
		return os << ']';
	}

	template <typename T>
	std::ostream& operator<<(std::ostream& os, Out<T> out)
	{
		++Log::s_outParamDepth;
		os << out.val;
		--Log::s_outParamDepth;
		return os;
	}

	void LogFormat(char * fmt, ...);
	void LogFormat(wchar_t * fmt, ...);
	void LogProcessNameAndPID();
	void LogOSVersion();
	void LogComputerManufacturer();
	void LogVideoCard();
}

template <typename T>
typename std::enable_if<std::is_class<T>::value && !std::is_same<T, std::string>::value, std::ostream&>::type
operator<<(std::ostream& os, const T& t)
{
	return os << static_cast<const void*>(&t);
}

template <typename T>
typename std::enable_if<std::is_class<T>::value, std::ostream&>::type
operator<<(std::ostream& os, T* t)
{
	if (!t)
	{
		return os << "null";
	}

	if (!Logging::Log::isPointerDereferencingAllowed())
	{
		return os << static_cast<const void*>(t);
	}

	return os << *t;
}

template <typename T>
std::ostream& operator<<(std::ostream& os, T** t)
{
	if (!t)
	{
		return os << "null";
	}

	os << static_cast<const void*>(t);

	if (Logging::Log::isPointerDereferencingAllowed())
	{
		os << '=' << *t;
	}

	return os;
}
