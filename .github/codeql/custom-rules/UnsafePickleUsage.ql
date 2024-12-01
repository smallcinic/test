import python

/**
 * Это правило обнаруживает небезопасное использование read_pickle() или pickle.load(),
 * где данные могут поступать из внешнего источника.
 */
class UnsafeReadPickleUsage extends python.Query {
    predicate isExternalInput(PythonCall call) {
        // Проверяем, идет ли чтение из файла или другого потенциально внешнего источника
        exists(PythonCall source |
            source.getCallee().getName() = "open" or
            source.getCallee().getName() = "input" or
            source.getCallee().getName() = "read" or
            source.getCallee().getName() = "sys.argv"
        )
    }

    predicate isPickleOrPandasUsage(PythonCall call) {
        call.getCallee().getName() = "read_pickle" or
        call.getCallee().getName() = "load" and
        call.getArgument(0).getType().hasName("file")
    }

    from PythonCall call
    where isPickleOrPandasUsage(call) and isExternalInput(call)
    select call, "Использование функции read_pickle() или pickle.load() с потенциально небезопасным вводом."
}
