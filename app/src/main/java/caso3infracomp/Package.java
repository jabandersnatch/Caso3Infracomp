package caso3infracomp;

public record Package(int idPackage, String nameClient, int state) {
    public String getState() {
        switch (state) {
            case -1:
                return "DESCONOCIDO";
            case 0:
                return "PKT_EN_OFICINA";
            case 1:
                return "PKT_RECOGIDO";
            case 2:
                return "PKT_EN_CLASIFICACION";
            case 3:
                return "PKT_DESPACHADO";
            case 4:
                return "PKT_EN_ENTREGA";
            case 5:
                return "PKT_ENTREGADO";
        }
        return "DESCONOCIDO";
    }
}
