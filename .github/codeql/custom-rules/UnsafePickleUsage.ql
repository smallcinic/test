import python

/**
 * Это правило находит вызовы pickle.load и read_pickle с возможными уязвимыми данными.
 * Важно, что мы будем искать использование небезопасных объектов, содержащих методы типа __reduce__.
 */
class UnsafePickleUsage extends python.Query {
    // Ищем использование pickle.load() или read_pickle()
    predicate isPickleUsage(PythonCall call) {
        call.getCallee().getName() = "load" and
        call.getArgument(0).getType().hasName("file")
    }

    // Проверяем наличие __reduce__ метода в классе
    predicate hasDangerousReduceMethod(PythonClass c) {
        exists(PythonMethod m | m.getDeclaringType() = c and
               m.getName() = "__reduce__" and
               m.getBody().toString().contains("os.system"))
    }

    from PythonCall call, PythonClass c
    where isPickleUsage(call) and
          exists(c, hasDangerousReduceMethod(c))
    select call, "Это использование pickle.load() или read_pickle() с потенциально небезопасным объектом."
}
